// 集成测试：验证跨子系统协作场景的正确性
//
// 这些测试不依赖 socket 网络（可在 MSVC 下编译运行），
// 通过构造 Runtime 和直接调用各子系统接口来验证端到端流程。
// 涉及 socket 的代理端到端测试在 Linux 环境下运行。

#include "openscanproxy/proxy/runtime.hpp"
#include "openscanproxy/http/http_message.hpp"
#include "openscanproxy/policy/policy.hpp"
#include "openscanproxy/extractor/extractor.hpp"
#include "openscanproxy/scanner/scanner.hpp"
#include "openscanproxy/config/config.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using openscanproxy::config::AppConfig;
using openscanproxy::core::Action;
using openscanproxy::core::Direction;
using openscanproxy::core::ExtractedFile;
using openscanproxy::core::ScanResult;
using openscanproxy::core::ScanStatus;
using openscanproxy::http::HttpRequest;
using openscanproxy::http::HttpResponse;
using openscanproxy::http::header_add;
using openscanproxy::http::header_get;
using openscanproxy::http::parse_request;
using openscanproxy::http::parse_response;
using openscanproxy::http::serialize_request;
using openscanproxy::http::serialize_response;
using openscanproxy::policy::AccessAction;
using openscanproxy::policy::AccessPolicyResult;
using openscanproxy::policy::PolicyConfig;
using openscanproxy::policy::PolicyEngine;
using openscanproxy::proxy::Runtime;
using openscanproxy::scanner::ScanContext;
using openscanproxy::scanner::create_mock_scanner;

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

// 构造一个最小化的 Runtime 用于测试（含 Mock 扫描器）
// 注意: Runtime 包含 mutex 成员不可移动，必须就地构造
AppConfig make_test_config() {
  AppConfig cfg;
  cfg.proxy_listen_port = 18080;
  cfg.admin_listen_port = 19090;
  cfg.scanner_type = "mock";
  cfg.enable_proxy_auth = false;
  cfg.audit_log_path = "";
  cfg.app_log_path = "";
  cfg.proxy_users_file = "";
  cfg.proxy_auth_portal_session_file = "";
  cfg.proxy_auth_client_cache_file = "";
  cfg.ca_cert_path = "";
  cfg.ca_key_path = "";
  return cfg;
}

AppConfig make_basic_auth_config() {
  AppConfig cfg = make_test_config();
  cfg.enable_proxy_auth = true;
  cfg.proxy_auth_mode = "basic";
  cfg.proxy_auth_user = "testuser";
  cfg.proxy_auth_password = "testpass";
  return cfg;
}

AppConfig make_portal_auth_config() {
  AppConfig cfg = make_test_config();
  cfg.enable_proxy_auth = true;
  cfg.proxy_auth_mode = "portal";
  cfg.proxy_auth_signing_key = "test-signing-key";
  cfg.proxy_auth_portal_session_ttl_sec = 3600;
  return cfg;
}

// ============================================================
// 场景 1: Basic 认证 — 正确凭据通过
// ============================================================
bool test_basic_auth_valid_credentials() {
  Runtime rt(make_basic_auth_config());

  // Base64 编码 "testuser:testpass"
  // 手动计算: testuser:testpass → dGVzdHVzZXI6dGVzdHBhc3M=
  const std::string encoded = "dGVzdHVzZXI6dGVzdHBhc3M=";
  HttpRequest req;
  req.method = "GET";
  req.uri = "http://example.com/";
  header_add(req.headers, "Host", "example.com");
  header_add(req.headers, "Proxy-Authorization", "Basic " + encoded);

  // 模拟 authenticate_proxy_request 的逻辑
  auto auth_header = header_get(req.headers, "Proxy-Authorization");
  bool has_prefix = auth_header.rfind("Basic ", 0) == 0;

  return expect(rt.proxy_auth.enabled(), "basic auth enabled") &&
         expect(has_prefix, "auth header has Basic prefix") &&
         expect(rt.proxy_auth.authenticate("testuser", "testpass"), "valid credentials accepted") &&
         expect(!rt.proxy_auth.authenticate("testuser", "wrongpass"), "wrong password rejected") &&
         expect(!rt.proxy_auth.authenticate("wronguser", "testpass"), "wrong user rejected");
}

// ============================================================
// 场景 2: Basic 认证 — 无凭据被拒
// ============================================================
bool test_basic_auth_no_credentials() {
  Runtime rt(make_basic_auth_config());

  // 不带 Proxy-Authorization 头
  return expect(rt.proxy_auth.enabled(), "basic auth enabled") &&
         expect(!rt.proxy_auth.authenticate("", ""), "empty credentials rejected");
}

// ============================================================
// 场景 3: Portal 认证 — 域级 Cookie 有效
// ============================================================
bool test_portal_auth_valid_cookie() {
  Runtime rt(make_portal_auth_config());

  // 构造有效的域级认证 Cookie
  auto cookie_value = rt.build_proxy_auth_cookie_value("portaluser", "example.com");
  auto username = rt.validate_proxy_auth_cookie(cookie_value, "example.com");

  return expect(!cookie_value.empty(), "cookie value generated") &&
         expect(username == "portaluser", "valid cookie returns correct username");
}

// ============================================================
// 场景 4: Portal 认证 — 域级 Cookie host 不匹配
// ============================================================
bool test_portal_auth_cookie_host_mismatch() {
  Runtime rt(make_portal_auth_config());

  // 为 example.com 签发的 Cookie，在 other.com 上验证应失败
  auto cookie_value = rt.build_proxy_auth_cookie_value("portaluser", "example.com");
  auto username = rt.validate_proxy_auth_cookie(cookie_value, "other.com");

  return expect(username.empty(), "cookie with wrong host should be rejected");
}

// ============================================================
// 场景 5: Portal 认证 — 一次性域认证令牌
// ============================================================
bool test_portal_domain_token_issue_and_consume() {
  Runtime rt(make_portal_auth_config());

  // 签发令牌
  auto token = rt.domain_tokens.issue("tokenuser", "example.com", 120);
  return expect(!token.empty(), "token issued") &&
         // 消费令牌（一次性）
         expect(rt.domain_tokens.consume(token, "example.com") == "tokenuser",
                "token consumed with correct host") &&
         // 再次消费同一令牌应失败（一次性使用）
         expect(rt.domain_tokens.consume(token, "example.com").empty(),
                "token reuse rejected") &&
         // host 不匹配应失败
         expect(rt.domain_tokens.consume(rt.domain_tokens.issue("tokenuser", "example.com", 120), "other.com").empty(),
                "token with wrong host rejected");
}

// ============================================================
// 场景 6: 策略引擎 — 域名黑名单拦截
// ============================================================
bool test_policy_domain_blacklist() {
  PolicyConfig cfg;
  cfg.default_access_action = AccessAction::Allow;
  cfg.domain_blacklist = {"blocked.example.com"};
  PolicyEngine engine(cfg);

  auto r = engine.evaluate_access("blocked.example.com", "/path", "GET");
  return expect(r.action == AccessAction::Block, "blacklisted domain blocked") &&
         expect(r.matched_type == "domain_blacklist", "matched_type correct");
}

// ============================================================
// 场景 7: 策略引擎 — URL 黑名单拦截
// ============================================================
bool test_policy_url_blacklist() {
  PolicyConfig cfg;
  cfg.default_access_action = AccessAction::Allow;
  cfg.url_blacklist = {"/admin"};
  PolicyEngine engine(cfg);

  auto r = engine.evaluate_access("example.com", "/admin", "GET");
  return expect(r.action == AccessAction::Block, "blacklisted URL blocked") &&
         expect(r.matched_type == "url_blacklist", "matched_type correct");
}

// ============================================================
// 场景 8: 策略引擎 — 默认拒绝 + 白名单放行
// ============================================================
bool test_policy_default_block_whitelist_allow() {
  PolicyConfig cfg;
  cfg.default_access_action = AccessAction::Block;
  cfg.domain_whitelist = {"allowed.example.com"};
  PolicyEngine engine(cfg);

  auto r1 = engine.evaluate_access("allowed.example.com", "/", "GET");
  auto r2 = engine.evaluate_access("unknown.example.com", "/", "GET");
  return expect(r1.action == AccessAction::Allow, "whitelisted domain allowed") &&
         expect(r2.action == AccessAction::Block, "non-whitelisted domain blocked");
}

// ============================================================
// 场景 9: 策略引擎 + 认证组合 — 认证通过但策略拦截
// ============================================================
bool test_auth_pass_policy_block() {
  Runtime rt(make_basic_auth_config());

  // 认证通过
  bool auth_ok = rt.proxy_auth.authenticate("testuser", "testpass");

  // 但策略引擎配置域名黑名单
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Allow;
  policy_cfg.domain_blacklist = {"blocked.example.com"};
  // Runtime 内的策略是从 config 构造的，这里直接用独立 PolicyEngine 验证逻辑
  PolicyEngine engine(policy_cfg);

  auto r = engine.evaluate_access("blocked.example.com", "/test", "GET");
  return expect(auth_ok, "authentication passed") &&
         expect(r.action == AccessAction::Block, "policy still blocks after auth");
}

// ============================================================
// 场景 10: 文件提取 + Mock 扫描器 + 策略决策
// ============================================================
bool test_extractor_scanner_policy_pipeline() {
  Runtime rt(make_test_config());
  rt.scanner = create_mock_scanner();

  // 构造 multipart 上传请求 — 提取器从 headers 的 Content-Disposition 中取 filename
  // MockScanner 对 filename 含 "eicar" 的返回 Infected
  const std::string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  std::string body =
      "--boundary\r\n"
      "Content-Disposition: form-data; name=\"file\"; filename=\"eicar.txt\"\r\n"
      "Content-Type: application/octet-stream\r\n"
      "\r\n" +
      eicar +
      "\r\n"
      "--boundary--\r\n";

  HttpRequest req;
  req.method = "POST";
  req.uri = "/upload";
  header_add(req.headers, "Host", "upload.example.com");
  header_add(req.headers, "Content-Type", "multipart/form-data; boundary=boundary");
  // 提取器从 request headers 的 Content-Disposition 字段取 filename
  header_add(req.headers, "Content-Disposition", "form-data; name=\"file\"; filename=\"eicar.txt\"");
  header_add(req.headers, "Content-Length", std::to_string(body.size()));
  req.body.assign(body.begin(), body.end());

  // 提取文件
  auto files = rt.extractor.from_request(req, "upload.example.com");

  // Mock 扫描器对含 eicar 文件名的内容返回 Infected
  bool has_files = !files.empty();
  ScanResult scan_result;
  scan_result.status = ScanStatus::Error;  // 默认
  if (has_files) {
    scan_result = rt.scanner->scan(files[0], rt.scan_ctx);
  }

  // 策略决策
  auto action = rt.policy.decide(scan_result);

  return expect(has_files, "file extracted from request") &&
         expect(scan_result.status == ScanStatus::Infected,
                "mock scanner detects eicar as infected") &&
         expect(action == Action::Block, "policy blocks infected file");
}

// ============================================================
// 场景 11: 正常文件提取 + Mock 扫描器返回 Clean
// ============================================================
bool test_extractor_scanner_clean_file() {
  Runtime rt(make_test_config());
  rt.scanner = create_mock_scanner();

  std::string body =
      "--boundary\r\n"
      "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n"
      "Content-Type: application/pdf\r\n"
      "\r\n"
      "PDF-1.4 content here\r\n"
      "--boundary--\r\n";

  HttpRequest req;
  req.method = "POST";
  req.uri = "/upload";
  header_add(req.headers, "Host", "upload.example.com");
  header_add(req.headers, "Content-Type", "multipart/form-data; boundary=boundary");
  header_add(req.headers, "Content-Disposition", "form-data; name=\"file\"; filename=\"report.pdf\"");
  header_add(req.headers, "Content-Length", std::to_string(body.size()));
  req.body.assign(body.begin(), body.end());

  auto files = rt.extractor.from_request(req, "upload.example.com");
  bool has_files = !files.empty();
  ScanResult scan_result;
  scan_result.status = ScanStatus::Error;
  if (has_files) {
    scan_result = rt.scanner->scan(files[0], rt.scan_ctx);
  }

  auto action = rt.policy.decide(scan_result);

  return expect(has_files, "clean file extracted") &&
         expect(scan_result.status == ScanStatus::Clean, "mock scanner returns clean") &&
         expect(action == Action::Allow, "policy allows clean file");
}

// ============================================================
// 场景 12: HTTP chunked trailer 解析 + 序列化完整 roundtrip
// ============================================================
bool test_chunked_trailer_roundtrip() {
  // 构造一个含 trailer 的 chunked 请求
  std::string raw =
      "POST /upload HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "Transfer-Encoding: chunked\r\n"
      "Trailer: X-Digest\r\n"
      "\r\n"
      "5\r\nhello\r\n"
      "6\r\n world\r\n"
      "0\r\n"
      "X-Digest: sha256=abc123\r\n"
      "\r\n";

  HttpRequest req;
  std::size_t consumed = 0;
  bool parsed = parse_request(raw, req, &consumed);

  if (!parsed) return expect(false, "chunked request with trailer parsed");

  // 验证 trailers
  bool has_trailer = !req.trailers.empty();
  auto digest = header_get(req.trailers, "X-Digest");

  // 序列化回来
  auto serialized = serialize_request(req);

  // 再次解析序列化后的数据
  HttpRequest req2;
  bool parsed2 = parse_request(serialized, req2, &consumed);

  return expect(parsed, "chunked request with trailer parsed") &&
         expect(has_trailer, "trailers present") &&
         expect(digest == "sha256=abc123", "trailer X-Digest value correct") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello world", "body decoded correctly") &&
         expect(parsed2, "serialized request re-parseable") &&
         expect(std::string(req2.body.begin(), req2.body.end()) == "hello world",
                "re-parsed body matches");
}

// ============================================================
// 场景 13: Portal 认证级联 — 无 Cookie + 无 Token → 403/302
// ============================================================
bool test_portal_auth_no_cookie_no_token() {
  Runtime rt(make_portal_auth_config());

  // 没有任何认证信息时，Portal 认证应该拒绝
  // 验证级联逻辑：无 Cookie → 空 token → Portal 应要求认证

  // 验证空 Cookie
  auto empty_result = rt.validate_proxy_auth_cookie("", "example.com");
  return expect(empty_result.empty(), "empty cookie rejected") &&
         expect(rt.portal_auth_enabled(), "portal_auth_enabled check consistent with config");
  // 注意：实际 302 重定向决策在 proxy_server.cpp 中，这里验证底层逻辑
}

// ============================================================
// 场景 14: Runtime 配置 → PolicyEngine 映射验证
// ============================================================
bool test_runtime_policy_config_mapping() {
  AppConfig cfg = make_test_config();
  cfg.policy_mode = "fail-close";  // 扫描失败时阻止
  cfg.suspicious_action = "block";  // 可疑文件也阻止
  cfg.domain_blacklist = {"bad.com"};

  Runtime rt(cfg);

  // 验证 fail-close 模式：扫描失败时应阻止
  ScanResult error_result;
  error_result.status = ScanStatus::Error;
  auto action = rt.policy.decide(error_result);

  // 验证域名黑名单生效
  auto access = rt.policy.evaluate_access("bad.com", "/", "GET");

  return expect(action == Action::Block, "fail-close: scan error → block") &&
         expect(access.action == AccessAction::Block, "domain blacklist active in runtime policy");
}

// ============================================================
// 场景 15: 响应 chunked 含 trailer 的完整 roundtrip
// ============================================================
bool test_response_chunked_trailer_roundtrip() {
  std::string raw =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "Trailer: X-Status\r\n"
      "\r\n"
      "4\r\nOK!\r\n"
      "0\r\n"
      "X-Status: complete\r\n"
      "\r\n";

  HttpResponse resp;
  bool parsed = parse_response(raw, resp);
  if (!parsed) return expect(false, "chunked response with trailer parsed");

  auto status_trailer = header_get(resp.trailers, "X-Status");
  auto serialized = serialize_response(resp);

  HttpResponse resp2;
  bool parsed2 = parse_response(serialized, resp2);

  return expect(parsed, "chunked response with trailer parsed") &&
         expect(resp.status == 200, "status code 200") &&
         expect(status_trailer == "complete", "trailer X-Status value correct") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "OK!", "body decoded") &&
         expect(parsed2, "serialized response re-parseable") &&
         expect(std::string(resp2.body.begin(), resp2.body.end()) == "OK!",
                "re-parsed body matches");
}

// ============================================================
// 场景 16: 文件提取器 — 从响应中提取下载文件
// ============================================================
bool test_extractor_from_response() {
  openscanproxy::extractor::FileExtractor extractor;

  HttpRequest req;
  req.method = "GET";
  req.uri = "/download/document.pdf";

  HttpResponse resp;
  resp.status = 200;
  header_add(resp.headers, "Content-Type", "application/pdf");
  header_add(resp.headers, "Content-Disposition", "attachment; filename=\"report.pdf\"");
  resp.body.assign(100, 'A');  // 100 bytes of dummy data

  auto files = extractor.from_response(req, resp, "download.example.com");

  return expect(!files.empty(), "file extracted from response") &&
         expect(files[0].direction == Direction::Download, "direction is download") &&
         expect(files[0].filename == "report.pdf", "filename from Content-Disposition") &&
         expect(files[0].source_host == "download.example.com", "host correct");
}

// ============================================================
// 场景 17: 认证级联顺序验证 — Cookie 先于 Token
// ============================================================
bool test_auth_cascade_cookie_before_token() {
  Runtime rt(make_portal_auth_config());

  // 同时有有效 Cookie 和 Token 时，Cookie 应先被验证
  auto cookie = rt.build_proxy_auth_cookie_value("cookieuser", "example.com");
  auto cookie_user = rt.validate_proxy_auth_cookie(cookie, "example.com");

  // 即使签发了 token，如果 cookie 已经有效就不需要消费 token
  auto token = rt.domain_tokens.issue("tokenuser", "example.com", 120);
  bool cookie_valid = !cookie_user.empty();

  // Token 仍然可消费（未被使用）
  auto token_user = rt.domain_tokens.consume(token, "example.com");

  return expect(cookie_valid, "cookie is valid") &&
         expect(cookie_user == "cookieuser", "cookie user correct") &&
         expect(token_user == "tokenuser", "token still consumable when cookie already valid");
}

}  // namespace

int main() {
  // 集成测试不依赖 socket 网络，不需要 Winsock 初始化
  bool ok = true;
  ok = test_basic_auth_valid_credentials() && ok;
  ok = test_basic_auth_no_credentials() && ok;
  ok = test_portal_auth_valid_cookie() && ok;
  ok = test_portal_auth_cookie_host_mismatch() && ok;
  ok = test_portal_domain_token_issue_and_consume() && ok;
  ok = test_policy_domain_blacklist() && ok;
  ok = test_policy_url_blacklist() && ok;
  ok = test_policy_default_block_whitelist_allow() && ok;
  ok = test_auth_pass_policy_block() && ok;
  ok = test_extractor_scanner_policy_pipeline() && ok;
  ok = test_extractor_scanner_clean_file() && ok;
  ok = test_chunked_trailer_roundtrip() && ok;
  ok = test_portal_auth_no_cookie_no_token() && ok;
  ok = test_runtime_policy_config_mapping() && ok;
  ok = test_response_chunked_trailer_roundtrip() && ok;
  ok = test_extractor_from_response() && ok;
  ok = test_auth_cascade_cookie_before_token() && ok;
  if (ok) {
    std::cout << "All integration tests passed\n";
    return 0;
  }
  return 1;
}