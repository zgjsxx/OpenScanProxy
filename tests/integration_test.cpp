// 集成测试：验证代理服务器端到端流程
// 包括 HTTP 正向代理、认证级联、策略拦截、CONNECT 隧道等场景

#include "openscanproxy/proxy/runtime.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using openscanproxy::config::AppConfig;
using openscanproxy::http::HttpRequest;
using openscanproxy::http::HttpResponse;
using openscanproxy::http::header_get;
using openscanproxy::http::parse_response;
using openscanproxy::policy::AccessAction;
using openscanproxy::policy::PolicyConfig;
using openscanproxy::proxy::ProxyServer;
using openscanproxy::proxy::Runtime;
using openscanproxy::core::split;

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

// --- Mock 上游 HTTP 服务器 ---
// 在后台线程监听指定端口，接收请求后返回固定响应。
// 记录最后一次收到的完整请求，供测试验证。
struct MockUpstreamServer {
  int listen_fd = -1;
  int port = 0;
  std::string response_body = "upstream-ok";
  std::string response_content_type = "text/plain";
  int response_status = 200;
  std::string response_reason = "OK";

  std::mutex mu;
  std::string last_request;
  bool running = false;
  std::thread server_thread;

  void start(int desired_port) {
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return;
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(desired_port));
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      close(listen_fd);
      listen_fd = -1;
      return;
    }
    // 如果用 0 端口，获取实际分配的端口
    socklen_t addrlen = sizeof(addr);
    getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &addrlen);
    port = ntohs(addr.sin_port);

    if (listen(listen_fd, 4) != 0) {
      close(listen_fd);
      listen_fd = -1;
      return;
    }
    running = true;
    server_thread = std::thread([this]() { serve(); });
  }

  void serve() {
    // 只处理一个连接，足够集成测试使用
    while (running) {
      sockaddr_in caddr{};
      socklen_t len = sizeof(caddr);
      int cfd = accept(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &len);
      if (cfd < 0) {
        if (!running) return;
        continue;
      }
      // 设置 recv 超时，避免测试挂起
      struct timeval tv{};
      tv.tv_sec = 5;
      tv.tv_usec = 0;
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

      std::string request;
      char buf[8192];
      // 读取请求（最多等待 5 秒）
      while (request.find("\r\n\r\n") == std::string::npos) {
        auto n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        request.append(buf, static_cast<std::size_t>(n));
      }

      // 解析 Content-Length 以读取 body
      auto header_end = request.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        std::istringstream hs(request.substr(0, header_end));
        std::string line;
        std::size_t content_length = 0;
        bool chunked = false;
        while (std::getline(hs, line)) {
          if (!line.empty() && line.back() == '\r') line.pop_back();
          if (line.find("Content-Length:") != std::string::npos) {
            try { content_length = std::stoull(line.substr(line.find(':') + 1)); } catch (...) {}
          }
          if (line.find("Transfer-Encoding:") != std::string::npos &&
              line.find("chunked") != std::string::npos) {
            chunked = true;
          }
        }

        if (chunked) {
          // 简单处理：继续读取直到遇到 0\r\n\r\n 或超时
          while (request.find("\r\n0\r\n\r\n") == std::string::npos &&
                 request.find("\r\n0\r\n") == std::string::npos) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<std::size_t>(n));
          }
        } else if (content_length > 0) {
          auto body_start = header_end + 4;
          while (request.size() < body_start + content_length) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<std::size_t>(n));
          }
        }
      }

      {
        std::lock_guard<std::mutex> lk(mu);
        last_request = request;
      }

      // 构造并发送响应
      std::ostringstream os;
      os << "HTTP/1.1 " << response_status << " " << response_reason << "\r\n"
         << "Content-Type: " << response_content_type << "\r\n"
         << "Content-Length: " << response_body.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << response_body;
      auto resp = os.str();
      send(cfd, resp.data(), resp.size(), 0);
      close(cfd);
    }
  }

  std::string get_last_request() {
    std::lock_guard<std::mutex> lk(mu);
    return last_request;
  }

  void stop() {
    running = false;
    if (listen_fd >= 0) {
      close(listen_fd);
      listen_fd = -1;
    }
    if (server_thread.joinable()) server_thread.join();
  }

  ~MockUpstreamServer() { stop(); }
};

// --- 测试 Fixture ---
// 构造最小 Runtime，配置代理端口和 Mock 上游服务器
struct TestProxy {
  MockUpstreamServer upstream;
  std::unique_ptr<Runtime> runtime;
  std::unique_ptr<ProxyServer> server;
  std::thread proxy_thread;
  int proxy_port = 0;
  int upstream_port = 0;
  bool started = false;

  // 全局端口偏移，每个 TestProxy 实例使用不同端口避免冲突
  // （代理线程 detach 后永远运行，旧端口不会释放）
  static int& port_offset() {
    static int offset = 0;
    return offset;
  }

  TestProxy() {
    proxy_port = 18080 + port_offset() * 2;
    upstream_port = 18081 + port_offset() * 2;
    ++port_offset();
  }

  // 创建默认测试配置
  static AppConfig make_config(int proxy_port, int upstream_port, bool enable_auth = false,
                               const std::string& auth_mode = "basic") {
    AppConfig cfg;
    cfg.proxy_listen_host = "127.0.0.1";
    cfg.proxy_listen_port = static_cast<uint16_t>(proxy_port);
    cfg.admin_listen_host = "127.0.0.1";
    cfg.admin_listen_port = 0;  // 不启动 admin
    cfg.enable_proxy_auth = enable_auth;
    cfg.proxy_auth_mode = auth_mode;
    cfg.proxy_auth_user = "testuser";
    cfg.proxy_auth_password = "testpass";
    cfg.scanner_type = "mock";
    cfg.enable_https_mitm = false;
    cfg.proxy_auth_signing_key = "test-signing-key";
    cfg.audit_log_path = "/dev/null";
    cfg.app_log_path = "/dev/null";
    cfg.app_log_level = "error";
    cfg.scan_upload = false;
    cfg.scan_download = false;
    return cfg;
  }

  // 启动代理（使用指定配置）
  void start_with_config(const AppConfig& cfg) {
    upstream.start(upstream_port);
    if (upstream.listen_fd < 0) {
      std::cerr << "WARN: upstream bind failed on port " << upstream_port << "\n";
      return;
    }

    runtime = std::make_unique<Runtime>(cfg);
    runtime->scanner = openscanproxy::scanner::create_mock_scanner();
    server = std::make_unique<ProxyServer>(*runtime);

    started = true;
    proxy_thread = std::thread([this]() { server->run(); });

    // 等待代理启动（最多 500ms）
    for (int i = 0; i < 50; ++i) {
      // 尝试连接代理端口，成功则说明已就绪
      int test_fd = socket(AF_INET, SOCK_STREAM, 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      addr.sin_port = htons(static_cast<uint16_t>(proxy_port));
      if (connect(test_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        close(test_fd);
        return;
      }
      close(test_fd);
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cerr << "WARN: proxy may not be ready on port " << proxy_port << "\n";
  }

  // 使用默认配置启动
  void start(bool enable_auth = false, const std::string& auth_mode = "basic") {
    auto cfg = make_config(proxy_port, upstream_port, enable_auth, auth_mode);
    start_with_config(cfg);
  }

  // 使用自定义策略配置启动
  void start_with_policy(const PolicyConfig& policy_cfg, bool enable_auth = false, const std::string& auth_mode = "basic") {
    auto cfg = make_config(proxy_port, upstream_port, enable_auth, auth_mode);
    start_with_config(cfg);
    // 更新策略引擎
    runtime->policy.update(policy_cfg);
  }

  ~TestProxy() {
    // 代理的 run() 是无限循环，无法优雅停止。
    // 进程退出时 detached 线程会被终止，这里只需关闭上游。
    if (proxy_thread.joinable()) proxy_thread.detach();
    upstream.stop();
  }

  // 发送原始请求到代理并读取响应
  std::string send_raw(const std::string& raw_request, int timeout_sec = 5) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";

    struct timeval tv{};
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(proxy_port));
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      close(fd);
      return "";
    }
    if (send(fd, raw_request.data(), raw_request.size(), 0) <= 0) {
      close(fd);
      return "";
    }

    std::string response;
    char buf[8192];
    while (true) {
      auto n = recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) break;
      response.append(buf, static_cast<std::size_t>(n));
      // 如果已收到完整响应头（对非 keepalive 场景），读取 body 后即可关闭
      auto hdr_end = response.find("\r\n\r\n");
      if (hdr_end != std::string::npos) {
        // 解析 Content-Length 判断是否读完
        std::istringstream hs(response.substr(0, hdr_end));
        std::string line;
        std::size_t cl = 0;
        bool has_cl = false;
        bool is_close = false;
        while (std::getline(hs, line)) {
          if (!line.empty() && line.back() == '\r') line.pop_back();
          std::string lower_line = line;
          std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(),
                         [](unsigned char c) { return std::tolower(c); });
          if (lower_line.find("content-length:") == 0) {
            try { cl = std::stoull(line.substr(line.find(':') + 1)); has_cl = true; } catch (...) {}
          }
          if (lower_line.find("connection: close") != std::string::npos ||
              lower_line.find("connection:close") != std::string::npos) {
            is_close = true;
          }
        }
        if (has_cl && response.size() >= hdr_end + 4 + cl) break;
        if (is_close && !has_cl && response.size() > hdr_end + 4) {
          // 连接关闭型响应，可能已经读完
          // 继续尝试读取，超时后自然退出
        }
      }
    }
    close(fd);
    return response;
  }

  // 发送请求并解析响应
  HttpResponse send_and_parse(const std::string& raw_request, int timeout_sec = 5) {
    auto raw = send_raw(raw_request, timeout_sec);
    HttpResponse resp;
    if (!raw.empty()) {
      parse_response(raw, resp);
    }
    return resp;
  }
};

std::string to_lower(const std::string& s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
  return out;
}

// Base64 编码（用于构造 Proxy-Authorization 头）
std::string base64_encode(const std::string& input) {
  static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(kTable[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) out.push_back(kTable[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

// ===================================================================
// 场景 1: 无认证 HTTP GET 请求转发
// ===================================================================
bool test_http_get_no_auth() {
  TestProxy tp;
  tp.start(false);  // 不启用认证

  // 构造 GET 请求，Host 指向上游服务器
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/test HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "http_get_no_auth: no response received");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "http_get_no_auth: failed to parse response");

  bool ok = true;
  ok = expect(resp.status == 200, "http_get_no_auth: status should be 200, got " + std::to_string(resp.status)) && ok;
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok",
              "http_get_no_auth: body should be 'upstream-ok'") && ok;

  // 验证上游确实收到了请求
  auto upstream_req = tp.upstream.get_last_request();
  ok = expect(!upstream_req.empty(), "http_get_no_auth: upstream should have received request") && ok;
  ok = expect(upstream_req.find("GET /test") != std::string::npos,
              "http_get_no_auth: upstream request should contain GET /test") && ok;

  return ok;
}

// ===================================================================
// 场景 2: HTTP POST 固定 body 转发
// ===================================================================
bool test_http_post_with_body() {
  TestProxy tp;
  tp.start(false);

  std::string body = "hello-post-body";
  std::ostringstream req;
  req << "POST http://127.0.0.1:" << tp.upstream_port << "/submit HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Content-Type: text/plain\r\n"
      << "Connection: close\r\n\r\n"
      << body;

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "http_post_with_body: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "http_post_with_body: failed to parse response");

  bool ok = true;
  ok = expect(resp.status == 200, "http_post_with_body: status should be 200") && ok;

  // 验证上游收到 POST 请求含 body
  auto upstream_req = tp.upstream.get_last_request();
  ok = expect(upstream_req.find("POST /submit") != std::string::npos,
              "http_post_with_body: upstream should have POST /submit") && ok;
  ok = expect(upstream_req.find(body) != std::string::npos,
              "http_post_with_body: upstream should have received body") && ok;

  return ok;
}

// ===================================================================
// 场景 3: HTTP chunked 请求转发（含 trailer）
// ===================================================================
bool test_http_chunked_with_trailer() {
  TestProxy tp;
  tp.start(false);

  std::ostringstream req;
  req << "POST http://127.0.0.1:" << tp.upstream_port << "/chunked HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Transfer-Encoding: chunked\r\n"
      << "Connection: close\r\n\r\n"
      << "5\r\nhello\r\n"
      << "6\r\n world\r\n"
      << "0\r\n"
      << "X-Digest: sha256=abc\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "http_chunked_with_trailer: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "http_chunked_with_trailer: failed to parse response");

  bool ok = true;
  ok = expect(resp.status == 200, "http_chunked_with_trailer: status should be 200") && ok;

  // 验证上游收到了请求（代理应该解码 chunked 后转发）
  auto upstream_req = tp.upstream.get_last_request();
  ok = expect(!upstream_req.empty(), "http_chunked_with_trailer: upstream should have received request") && ok;

  return ok;
}

// ===================================================================
// 场景 4: Pipeline 请求处理
// ===================================================================
bool test_http_pipeline() {
  TestProxy tp;
  tp.start(false);

  // 发送两个请求（注意：代理的 handle_client 支持 pipeline 循环）
  // 但上游 mock 服务器每连接只处理一个请求然后关闭连接
  // 所以实际只能验证第一个请求成功转发
  std::ostringstream req1;
  req1 << "GET http://127.0.0.1:" << tp.upstream_port << "/first HTTP/1.1\r\n"
       << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n\r\n";

  auto raw_resp = tp.send_raw(req1.str());
  if (raw_resp.empty()) return expect(false, "http_pipeline: no response for first request");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "http_pipeline: failed to parse first response");

  bool ok = expect(resp.status == 200, "http_pipeline: first request should return 200") ;

  auto upstream_req = tp.upstream.get_last_request();
  ok = expect(upstream_req.find("/first") != std::string::npos,
              "http_pipeline: upstream should have received /first") && ok;

  return ok;
}

// ===================================================================
// 场景 5: Basic 认证 — 正确凭据
// ===================================================================
bool test_basic_auth_valid() {
  TestProxy tp;
  tp.start(true, "basic");  // 启用 Basic 认证

  auto cred = base64_encode("testuser:testpass");
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/auth HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Proxy-Authorization: Basic " << cred << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "basic_auth_valid: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "basic_auth_valid: failed to parse response");

  // 正确凭据应正常转发（200），而非返回 407
  bool ok = expect(resp.status == 200, "basic_auth_valid: status should be 200, got " + std::to_string(resp.status));
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok",
              "basic_auth_valid: body should be 'upstream-ok'") && ok;

  return ok;
}

// ===================================================================
// 场景 6: Basic 认证 — 错误凭据
// ===================================================================
bool test_basic_auth_invalid() {
  TestProxy tp;
  tp.start(true, "basic");

  auto bad_cred = base64_encode("testuser:wrongpass");
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/auth HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Proxy-Authorization: Basic " << bad_cred << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "basic_auth_invalid: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "basic_auth_invalid: failed to parse response");

  return expect(resp.status == 407, "basic_auth_invalid: status should be 407, got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 7: Basic 认证 — 无凭据
// ===================================================================
bool test_basic_auth_none() {
  TestProxy tp;
  tp.start(true, "basic");

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/auth HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "basic_auth_none: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "basic_auth_none: failed to parse response");

  return expect(resp.status == 407, "basic_auth_none: status should be 407, got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 8: Portal 认证 — 域级 Cookie 有效
// ===================================================================
bool test_portal_cookie_valid() {
  TestProxy tp;
  tp.start(true, "portal");  // portal 模式启用 Basic + Portal

  // 使用 Runtime 构造有效的域级 Cookie
  std::string host = "127.0.0.1";
  auto cookie_value = tp.runtime->build_proxy_auth_cookie_value("portaluser", host);

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/portal HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Cookie: osp_proxy_auth_insecure=" << cookie_value << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "portal_cookie_valid: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "portal_cookie_valid: failed to parse response");

  bool ok = expect(resp.status == 200, "portal_cookie_valid: status should be 200, got " + std::to_string(resp.status));
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok",
              "portal_cookie_valid: body should be 'upstream-ok'") && ok;
  return ok;
}

// ===================================================================
// 场景 9: Portal 认证 — 域级 Cookie 过期
// ===================================================================
bool test_portal_cookie_expired() {
  TestProxy tp;
  tp.start(true, "portal");

  // 手工构造一个已过期的 Cookie（exp_seconds = 1，早已过期）
  std::string host = "127.0.0.1";
  auto parts = openscanproxy::core::split(tp.runtime->build_proxy_auth_cookie_value("portaluser", host), '|');
  // 替换 exp_seconds 为 1（过期时间）
  std::string expired_cookie = "portaluser|1|" + parts[2];

  // 浏览器风格的请求（带 User-Agent + Accept: text/html），应触发 Portal 重定向
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/expired HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Cookie: osp_proxy_auth_insecure=" << expired_cookie << "\r\n"
      << "User-Agent: Mozilla/5.0\r\n"
      << "Accept: text/html\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "portal_cookie_expired: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "portal_cookie_expired: failed to parse response");

  // 过期 Cookie + 浏览器请求 → 302 重定向到 Portal 或 403
  bool ok = expect(resp.status == 302 || resp.status == 403,
                   "portal_cookie_expired: status should be 302 or 403, got " + std::to_string(resp.status));
  return ok;
}

// ===================================================================
// 场景 10: Portal 认证 — 无认证浏览器请求触发重定向
// ===================================================================
bool test_portal_redirect_browser() {
  TestProxy tp;
  tp.start(true, "portal");

  // 浏览器风格请求（不带认证信息，但带 User-Agent 和 Accept: text/html）
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/page HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "User-Agent: Mozilla/5.0\r\n"
      << "Accept: text/html\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "portal_redirect_browser: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "portal_redirect_browser: failed to parse response");

  bool ok = expect(resp.status == 302, "portal_redirect_browser: status should be 302, got " + std::to_string(resp.status));
  auto location = header_get(resp.headers, "Location");
  ok = expect(!location.empty(), "portal_redirect_browser: should have Location header") && ok;
  ok = expect(location.find("/login") != std::string::npos,
              "portal_redirect_browser: Location should point to portal login") && ok;
  return ok;
}

// ===================================================================
// 场景 11: 域名黑名单拦截
// ===================================================================
bool test_domain_blacklist_block() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Allow;
  policy_cfg.domain_blacklist = {"blocked.example.com"};

  TestProxy tp;
  tp.start_with_policy(policy_cfg);

  std::ostringstream req;
  req << "GET http://blocked.example.com/test HTTP/1.1\r\n"
      << "Host: blocked.example.com\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "domain_blacklist_block: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "domain_blacklist_block: failed to parse response");

  bool ok = expect(resp.status == 403, "domain_blacklist_block: status should be 403, got " + std::to_string(resp.status));
  auto body_str = std::string(resp.body.begin(), resp.body.end());
  ok = expect(body_str.find("Blocked") != std::string::npos || body_str.find("403") != std::string::npos,
              "domain_blacklist_block: body should mention blocked") && ok;
  return ok;
}

// ===================================================================
// 场景 12: URL 黑名单拦截
// ===================================================================
bool test_url_blacklist_block() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Allow;
  // URL 黑名单中的规则需要与代理传入的 req.uri 匹配
  // HTTP 正向代理的 req.uri 是绝对 URL（如 http://host/path）
  // match_rule 支持前缀匹配：规则以 "/" 结尾时可匹配以此前缀开头的 URL
  policy_cfg.url_blacklist = {"http://blocked.example.com/admin/"};

  TestProxy tp;
  tp.start_with_policy(policy_cfg);

  // 请求一个在黑名单 URL 前缀下的路径，但域名不在域名黑名单中
  std::ostringstream req;
  req << "GET http://blocked.example.com/admin/panel HTTP/1.1\r\n"
      << "Host: blocked.example.com\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "url_blacklist_block: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "url_blacklist_block: failed to parse response");

  return expect(resp.status == 403, "url_blacklist_block: status should be 403, got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 13: 域名白名单放行（默认拒绝）
// ===================================================================
bool test_domain_whitelist_allow() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Block;
  policy_cfg.domain_whitelist = {"127.0.0.1"};

  TestProxy tp;
  tp.start_with_policy(policy_cfg);

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/allowed HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "domain_whitelist_allow: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "domain_whitelist_allow: failed to parse response");

  bool ok = expect(resp.status == 200, "domain_whitelist_allow: whitelisted domain should return 200, got " + std::to_string(resp.status));
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok",
              "domain_whitelist_allow: body should be 'upstream-ok'") && ok;
  return ok;
}

// ===================================================================
// 场景 14: CONNECT 隧道（无 MITM）— 验证 200 Connection Established
// ===================================================================
bool test_connect_tunnel_no_mitm() {
  TestProxy tp;
  tp.start(false);

  // CONNECT 请求指向一个目标（注意：需要目标服务器可达才能完成隧道）
  // 这里只验证代理返回 200 Connection Established
  std::ostringstream req;
  req << "CONNECT 127.0.0.1:" << tp.upstream_port << " HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n\r\n";

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return expect(false, "connect_tunnel_no_mitm: socket failed");

  struct timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(tp.proxy_port));
  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return expect(false, "connect_tunnel_no_mitm: connect failed");
  }

  if (send(fd, req.str().data(), req.str().size(), 0) <= 0) {
    close(fd);
    return expect(false, "connect_tunnel_no_mitm: send failed");
  }

  // 读取代理对 CONNECT 的响应（期望 200 Connection Established）
  char buf[8192];
  std::string response;
  while (response.find("\r\n\r\n") == std::string::npos) {
    auto n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  close(fd);

  bool ok = expect(!response.empty(), "connect_tunnel_no_mitm: should receive response");
  ok = expect(response.find("200") != std::string::npos,
              "connect_tunnel_no_mitm: should contain 200") && ok;
  ok = expect(response.find("Connection Established") != std::string::npos,
              "connect_tunnel_no_mitm: should contain 'Connection Established'") && ok;
  return ok;
}

// ===================================================================
// 场景 15: CONNECT 隧道 — 认证失败返回 407
// ===================================================================
bool test_connect_tunnel_auth_required() {
  TestProxy tp;
  tp.start(true, "basic");

  // 不带凭据发送 CONNECT
  std::ostringstream req;
  req << "CONNECT example.com:443 HTTP/1.1\r\n"
      << "Host: example.com:443\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "connect_tunnel_auth_required: no response");

  HttpResponse resp;
  // 代理的 407 响应可能不是标准 HTTP 响应格式（直接发送的字符串）
  // 尝试解析，如果失败则直接检查原始内容
  if (parse_response(raw_resp, resp)) {
    return expect(resp.status == 407, "connect_tunnel_auth_required: status should be 407, got " + std::to_string(resp.status));
  }
  // 直接检查原始响应内容
  return expect(raw_resp.find("407") != std::string::npos,
                "connect_tunnel_auth_required: raw response should contain 407");
}

// ===================================================================
// 场景 16: 子资源请求不触发 Portal 重定向
// ===================================================================
bool test_portal_no_redirect_for_script() {
  TestProxy tp;
  tp.start(true, "portal");

  // 脚本请求（Sec-Fetch-Dest: script）不应触发 Portal 重定向
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << tp.upstream_port << "/script.js HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << tp.upstream_port << "\r\n"
      << "User-Agent: Mozilla/5.0\r\n"
      << "Sec-Fetch-Dest: script\r\n"
      << "Sec-Fetch-Mode: no-cors\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "portal_no_redirect_script: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "portal_no_redirect_script: failed to parse response");

  // 子资源请求不应返回 302 重定向到 Portal
  // 应返回 403（Portal Auth Required）或 407（Basic fallback）
  bool ok = expect(resp.status != 302,
                   "portal_no_redirect_script: script request should NOT get 302 redirect, got " + std::to_string(resp.status));
  return ok;
}

// ===================================================================
// 场景 17: 认证 + 策略组合 — 认证通过但策略拦截
// ===================================================================
bool test_auth_pass_but_policy_block() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Allow;
  policy_cfg.domain_blacklist = {"blocked.example.com"};

  TestProxy tp;
  tp.start_with_policy(policy_cfg, true, "basic");

  auto cred = base64_encode("testuser:testpass");
  std::ostringstream req;
  req << "GET http://blocked.example.com/test HTTP/1.1\r\n"
      << "Host: blocked.example.com\r\n"
      << "Proxy-Authorization: Basic " << cred << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "auth_pass_policy_block: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "auth_pass_policy_block: failed to parse response");

  // 认证通过但策略应拦截 → 403
  return expect(resp.status == 403, "auth_pass_policy_block: status should be 403, got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 18: 访问策略 — 默认拒绝 + 白名单放行 + 黑名单优先
// ===================================================================
bool test_policy_blacklist_over_whitelist() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Block;
  policy_cfg.domain_whitelist = {"mixed.example.com"};
  policy_cfg.domain_blacklist = {"mixed.example.com"};  // 黑名单应优先于白名单

  TestProxy tp;
  tp.start_with_policy(policy_cfg);

  std::ostringstream req;
  req << "GET http://mixed.example.com/test HTTP/1.1\r\n"
      << "Host: mixed.example.com\r\n"
      << "Connection: close\r\n\r\n";

  auto raw_resp = tp.send_raw(req.str());
  if (raw_resp.empty()) return expect(false, "policy_blacklist_over_whitelist: no response");

  HttpResponse resp;
  if (!parse_response(raw_resp, resp)) return expect(false, "policy_blacklist_over_whitelist: failed to parse response");

  return expect(resp.status == 403, "policy_blacklist_over_whitelist: blacklist should override whitelist, got " + std::to_string(resp.status));
}

}  // namespace

int main() {
  bool ok = true;
  std::cout << "Running integration tests...\n\n";

  ok = test_http_get_no_auth() && ok;
  ok = test_http_post_with_body() && ok;
  ok = test_http_chunked_with_trailer() && ok;
  ok = test_http_pipeline() && ok;
  ok = test_basic_auth_valid() && ok;
  ok = test_basic_auth_invalid() && ok;
  ok = test_basic_auth_none() && ok;
  ok = test_portal_cookie_valid() && ok;
  ok = test_portal_cookie_expired() && ok;
  ok = test_portal_redirect_browser() && ok;
  ok = test_domain_blacklist_block() && ok;
  ok = test_url_blacklist_block() && ok;
  ok = test_domain_whitelist_allow() && ok;
  ok = test_connect_tunnel_no_mitm() && ok;
  ok = test_connect_tunnel_auth_required() && ok;
  ok = test_portal_no_redirect_for_script() && ok;
  ok = test_auth_pass_but_policy_block() && ok;
  ok = test_policy_blacklist_over_whitelist() && ok;

  std::cout << "\n";
  if (ok) {
    std::cout << "All integration tests passed\n";
    return 0;
  }
  return 1;
}