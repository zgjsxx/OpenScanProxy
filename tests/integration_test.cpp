// 集成测试：验证代理服务器端到端流程
//
// 架构：
//   每个测试函数启动三个线程：
//   1. mock_upstream: 简单 HTTP 服务器，监听指定端口，返回固定 200 OK
//   2. proxy: ProxyServer::run() 在后台线程
//   3. main: 测试主线程，作为 TCP 客户端
//
//   流程: client → proxy → upstream → proxy → client
//
//   时序保证：先启动 upstream，wait_for_port 确认就绪后再启动 proxy

#include "openscanproxy/proxy/runtime.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/http/http_message.hpp"
#include "openscanproxy/core/logger.hpp"

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

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

// 等待 TCP 端口可连接（说明服务已就绪）
bool wait_for_port(int port, int timeout_ms = 2000) {
  for (int i = 0; i < timeout_ms / 20; ++i) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
      close(fd);
      return true;
    }
    close(fd);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

// 启动一个简单的 mock 上游 HTTP 服务器
// 监听指定端口，每收到一个请求就返回 "HTTP/1.1 200 OK\r\n...\r\nupstream-ok"
// 在后台线程运行，stop() 关闭监听 fd 终止线程
struct MockUpstream {
  int listen_fd = -1;
  int port = 0;
  std::thread thread;
  bool running = false;
  std::mutex mu;
  std::string last_request;

  // 启动并等待就绪
  bool start_and_wait(int desired_port, int timeout_ms = 2000) {
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return false;
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(desired_port));
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      close(listen_fd); listen_fd = -1; return false;
    }
    socklen_t alen = sizeof(addr);
    getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &alen);
    port = ntohs(addr.sin_port);
    if (listen(listen_fd, 4) != 0) {
      close(listen_fd); listen_fd = -1; return false;
    }
    running = true;
    thread = std::thread([this]() { serve(); });
    // 等上游就绪：反复尝试 connect 到自己
    for (int i = 0; i < timeout_ms / 10; ++i) {
      int fd2 = socket(AF_INET, SOCK_STREAM, 0);
      sockaddr_in a2{};
      a2.sin_family = AF_INET;
      a2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      a2.sin_port = htons(static_cast<uint16_t>(port));
      if (connect(fd2, reinterpret_cast<sockaddr*>(&a2), sizeof(a2)) == 0) {
        close(fd2);
        return true;  // 上游已就绪
      }
      close(fd2);
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;  // 超时
  }

  void serve() {
    while (running) {
      sockaddr_in caddr{};
      socklen_t len = sizeof(caddr);
      int cfd = accept(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &len);
      if (cfd < 0) {
        if (!running) return;
        continue;
      }
      struct timeval tv{};
      tv.tv_sec = 5;
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

      // 读取请求直到 header 结束
      std::string req;
      char buf[8192];
      while (req.find("\r\n\r\n") == std::string::npos) {
        auto n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        req.append(buf, static_cast<std::size_t>(n));
      }
      // 读取 body（如果有 Content-Length）
      auto hdr_end = req.find("\r\n\r\n");
      if (hdr_end != std::string::npos) {
        std::istringstream hs(req.substr(0, hdr_end));
        std::string line;
        std::size_t cl = 0;
        bool chunked = false;
        while (std::getline(hs, line)) {
          if (!line.empty() && line.back() == '\r') line.pop_back();
          std::string lo = line;
          std::transform(lo.begin(), lo.end(), lo.begin(), [](unsigned char c){ return std::tolower(c); });
          if (lo.find("content-length:") == 0) {
            try { cl = std::stoull(line.substr(line.find(':') + 1)); } catch (...) {}
          }
          if (lo.find("transfer-encoding:") == 0 && lo.find("chunked") != std::string::npos) chunked = true;
        }
        if (chunked) {
          while (req.find("\r\n0\r\n") == std::string::npos) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<std::size_t>(n));
          }
        } else if (cl > 0) {
          while (req.size() < hdr_end + 4 + cl) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<std::size_t>(n));
          }
        }
      }

      {
        std::lock_guard<std::mutex> lk(mu);
        last_request = req;
      }

      // 返回固定响应
      std::string body = "upstream-ok";
      std::ostringstream os;
      os << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/plain\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << body;
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
    if (listen_fd >= 0) { close(listen_fd); listen_fd = -1; }
    if (thread.joinable()) thread.join();
  }
};

// TCP 客户端：发送请求，读取直到 EOF（代理 close 连接）
std::string tcp_send_recv_all(int port, const std::string& request, int timeout_sec = 5) {
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
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { close(fd); return ""; }
  if (send(fd, request.data(), request.size(), 0) <= 0) { close(fd); return ""; }

  std::string response;
  char buf[8192];
  while (true) {
    auto n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  close(fd);
  return response;
}

int parse_status(const std::string& raw) {
  if (raw.empty()) return -1;
  auto le = raw.find("\r\n");
  if (le == std::string::npos) le = raw.find("\n");
  auto fl = (le != std::string::npos) ? raw.substr(0, le) : raw;
  std::istringstream iss(fl);
  std::string ver; int st = -1;
  iss >> ver >> st;
  return st;
}

HttpResponse parse_resp(const std::string& raw) {
  HttpResponse r;
  if (!raw.empty()) parse_response(raw, r);
  return r;
}

std::string b64(const std::string& in) {
  static constexpr char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -6;
  for (unsigned char c : in) { val = (val << 8) + c; valb += 8; while (valb >= 0) { out.push_back(T[(val >> valb) & 0x3F]); valb -= 6; } }
  if (valb > -6) out.push_back(T[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

AppConfig make_cfg(int proxy_port, bool auth = false, const std::string& mode = "basic") {
  AppConfig c;
  c.proxy_listen_host = "127.0.0.1";
  c.proxy_listen_port = static_cast<uint16_t>(proxy_port);
  c.enable_proxy_auth = auth;
  c.proxy_auth_mode = mode;
  c.proxy_auth_user = "testuser";
  c.proxy_auth_password = "testpass";
  c.scanner_type = "mock";
  c.enable_https_mitm = false;
  c.proxy_auth_signing_key = "test-signing-key";
  c.audit_log_path = "/dev/null";
  c.app_log_path = "/dev/null";
  c.app_log_level = "error";
  c.scan_upload = false;
  c.scan_download = false;
  return c;
}

// ===================================================================
// 场景 1: 无认证 HTTP GET → 200（完整转发链路）
// ===================================================================
bool test_http_get_no_auth() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18181)) return expect(false, "http_get_no_auth: upstream not ready");

  const int port = 18080;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "http_get_no_auth: proxy not ready"); }

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << upstream.port << "/test HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "http_get_no_auth: no response");
  HttpResponse resp = parse_resp(raw);
  bool ok = expect(resp.status == 200, "http_get_no_auth: should be 200, got " + std::to_string(resp.status));
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok", "http_get_no_auth: body should be upstream-ok") && ok;

  auto ur = upstream.get_last_request();
  ok = expect(!ur.empty(), "http_get_no_auth: upstream should receive request") && ok;
  ok = expect(ur.find("GET /test") != std::string::npos, "http_get_no_auth: upstream request should have GET /test") && ok;
  return ok;
}

// ===================================================================
// 场景 2: HTTP POST body 转发 → 200
// ===================================================================
bool test_http_post_with_body() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18182)) return expect(false, "post_with_body: upstream not ready");

  const int port = 18082;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "post_with_body: proxy not ready"); }

  std::string body = "hello-post-body";
  std::ostringstream req;
  req << "POST http://127.0.0.1:" << upstream.port << "/submit HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Content-Type: text/plain\r\n"
      << "Connection: close\r\n\r\n" << body;

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "post_with_body: no response");
  HttpResponse resp = parse_resp(raw);
  bool ok = expect(resp.status == 200, "post_with_body: should be 200, got " + std::to_string(resp.status));
  auto ur = upstream.get_last_request();
  ok = expect(ur.find("POST /submit") != std::string::npos, "post_with_body: upstream should have POST") && ok;
  ok = expect(ur.find(body) != std::string::npos, "post_with_body: upstream should have body") && ok;
  return ok;
}

// ===================================================================
// 场景 3: Basic 认证 — 无凭据 → 407
// ===================================================================
bool test_basic_auth_no_creds() {
  const int port = 18084;
  auto cfg = make_cfg(port, true, "basic");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "basic_no_creds: proxy not ready"); }

  std::string req = "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "basic_no_creds: no response");
  return expect(parse_status(raw) == 407, "basic_no_creds: should be 407, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 4: Basic 认证 — 错误凭据 → 407
// ===================================================================
bool test_basic_auth_bad_creds() {
  const int port = 18086;
  auto cfg = make_cfg(port, true, "basic");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "basic_bad_creds: proxy not ready"); }

  auto cred = b64("testuser:wrongpass");
  std::string req = "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + cred + "\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "basic_bad_creds: no response");
  return expect(parse_status(raw) == 407, "basic_bad_creds: should be 407, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 5: Basic 认证 — 正确凭据 → 200（转发到上游）
// ===================================================================
bool test_basic_auth_valid_creds() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18185)) return expect(false, "basic_valid: upstream not ready");

  const int port = 18088;
  auto cfg = make_cfg(port, true, "basic");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "basic_valid: proxy not ready"); }

  auto cred = b64("testuser:testpass");
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << upstream.port << "/auth HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Proxy-Authorization: Basic " << cred << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "basic_valid: no response");
  HttpResponse resp = parse_resp(raw);
  return expect(resp.status == 200, "basic_valid: should be 200 (forwarded), got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 6: 域名黑名单 → 403
// ===================================================================
bool test_domain_blacklist_block() {
  const int port = 18090;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Allow; pc.domain_blacklist = {"blocked.example.com"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "domain_blacklist: proxy not ready"); }

  std::string req = "GET http://blocked.example.com/test HTTP/1.1\r\nHost: blocked.example.com\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "domain_blacklist: no response");
  return expect(parse_status(raw) == 403, "domain_blacklist: should be 403, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 7: URL 黑名单 → 403
// ===================================================================
bool test_url_blacklist_block() {
  const int port = 18092;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Allow; pc.url_blacklist = {"http://blocked.example.com/admin/"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "url_blacklist: proxy not ready"); }

  std::string req = "GET http://blocked.example.com/admin/panel HTTP/1.1\r\nHost: blocked.example.com\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "url_blacklist: no response");
  return expect(parse_status(raw) == 403, "url_blacklist: should be 403, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 8: 域名白名单放行（默认拒绝）→ 200（转发到上游）
// ===================================================================
bool test_domain_whitelist_allow() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18188)) return expect(false, "whitelist_allow: upstream not ready");

  const int port = 18094;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Block; pc.domain_whitelist = {"127.0.0.1"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "whitelist_allow: proxy not ready"); }

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << upstream.port << "/ok HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "whitelist_allow: no response");
  HttpResponse resp = parse_resp(raw);
  bool ok = expect(resp.status == 200, "whitelist_allow: should be 200, got " + std::to_string(resp.status));
  ok = expect(std::string(resp.body.begin(), resp.body.end()) == "upstream-ok", "whitelist_allow: body should be upstream-ok") && ok;
  return ok;
}

// ===================================================================
// 场景 9: 默认拒绝 + 非白名单 → 403
// ===================================================================
bool test_default_block_non_whitelisted() {
  const int port = 18096;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Block; pc.domain_whitelist = {"allowed.example.com"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "default_block: proxy not ready"); }

  std::string req = "GET http://other.example.com/test HTTP/1.1\r\nHost: other.example.com\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "default_block: no response");
  return expect(parse_status(raw) == 403, "default_block: should be 403, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 10: 黑名单优先于白名单 → 403
// ===================================================================
bool test_blacklist_over_whitelist() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18190)) return expect(false, "bl_over_wl: upstream not ready");

  const int port = 18098;
  auto cfg = make_cfg(port);
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Allow;
  pc.domain_whitelist = {"127.0.0.1"}; pc.domain_blacklist = {"127.0.0.1"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "bl_over_wl: proxy not ready"); }

  std::ostringstream req;
  req << "GET http://127.0.0.1:" << upstream.port << "/test HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "bl_over_wl: no response");
  return expect(parse_status(raw) == 403, "bl_over_wl: blacklist should override whitelist, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 11: Portal 认证 — 浏览器请求 → 302 重定向
// ===================================================================
bool test_portal_redirect_browser() {
  const int port = 18100;
  auto cfg = make_cfg(port, true, "portal");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "portal_redirect: proxy not ready"); }

  std::string req = "GET http://example.com/page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "portal_redirect: no response");
  HttpResponse resp = parse_resp(raw);
  bool ok = expect(resp.status == 302, "portal_redirect: should be 302, got " + std::to_string(resp.status));
  auto loc = header_get(resp.headers, "Location");
  ok = expect(!loc.empty(), "portal_redirect: should have Location") && ok;
  ok = expect(loc.find("/login") != std::string::npos, "portal_redirect: Location should point to login") && ok;
  return ok;
}

// ===================================================================
// 场景 12: Portal 认证 — 子资源请求 → 403（不重定向）
// ===================================================================
bool test_portal_no_redirect_for_script() {
  const int port = 18102;
  auto cfg = make_cfg(port, true, "portal");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "portal_no_redirect: proxy not ready"); }

  std::string req = "GET http://example.com/script.js HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nSec-Fetch-Dest: script\r\nSec-Fetch-Mode: no-cors\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "portal_no_redirect: no response");
  return expect(parse_status(raw) == 403, "portal_no_redirect: should be 403 not 302, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 13: Portal Cookie 有效 → 200（转发到上游）
// ===================================================================
bool test_portal_cookie_valid() {
  MockUpstream upstream;
  if (!upstream.start_and_wait(18183)) return expect(false, "portal_cookie: upstream not ready");

  const int port = 18104;
  auto cfg = make_cfg(port, true, "portal");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); upstream.stop(); return expect(false, "portal_cookie: proxy not ready"); }

  auto cookie_value = runtime.build_proxy_auth_cookie_value("portaluser", "127.0.0.1");
  std::ostringstream req;
  req << "GET http://127.0.0.1:" << upstream.port << "/portal HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n"
      << "Cookie: osp_proxy_auth_insecure=" << cookie_value << "\r\n"
      << "Connection: close\r\n\r\n";

  auto raw = tcp_send_recv_all(port, req.str());
  proxy_thread.detach();
  upstream.stop();

  if (raw.empty()) return expect(false, "portal_cookie: no response");
  HttpResponse resp = parse_resp(raw);
  return expect(resp.status == 200, "portal_cookie: valid cookie should forward (200), got " + std::to_string(resp.status));
}

// ===================================================================
// 场景 14: Portal Cookie 过期 → 302 或 403
// ===================================================================
bool test_portal_cookie_expired() {
  const int port = 18106;
  auto cfg = make_cfg(port, true, "portal");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "portal_expired: proxy not ready"); }

  std::string req = "GET http://example.com/expired HTTP/1.1\r\nHost: example.com\r\nCookie: osp_proxy_auth_insecure=portaluser|1|badsig\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "portal_expired: no response");
  int st = parse_status(raw);
  return expect(st == 302 || st == 403, "portal_expired: should be 302 or 403, got " + std::to_string(st));
}

// ===================================================================
// 场景 15: 认证通过 + 策略拦截 → 403
// ===================================================================
bool test_auth_pass_policy_block() {
  const int port = 18108;
  auto cfg = make_cfg(port, true, "basic");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  PolicyConfig pc; pc.default_access_action = AccessAction::Allow; pc.domain_blacklist = {"blocked.example.com"};
  runtime.policy.update(pc);

  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "auth_policy: proxy not ready"); }

  auto cred = b64("testuser:testpass");
  std::string req = "GET http://blocked.example.com/test HTTP/1.1\r\nHost: blocked.example.com\r\nProxy-Authorization: Basic " + cred + "\r\nConnection: close\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "auth_policy: no response");
  return expect(parse_status(raw) == 403, "auth_policy: auth pass but policy block → 403, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 16: CONNECT 隧道 — 认证失败 → 407
// ===================================================================
bool test_connect_auth_required() {
  const int port = 18110;
  auto cfg = make_cfg(port, true, "basic");
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "connect_auth: proxy not ready"); }

  std::string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
  auto raw = tcp_send_recv_all(port, req);
  proxy_thread.detach();

  if (raw.empty()) return expect(false, "connect_auth: no response");
  return expect(parse_status(raw) == 407, "connect_auth: should be 407, got " + std::to_string(parse_status(raw)));
}

// ===================================================================
// 场景 17: CONNECT 隧道 — 无 MITM → 200 Connection Established
// ===================================================================
bool test_connect_tunnel_no_mitm() {
  const int port = 18112;
  auto cfg = make_cfg(port);
  cfg.enable_https_mitm = false;
  openscanproxy::core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

  Runtime runtime(cfg);
  runtime.scanner = openscanproxy::scanner::create_mock_scanner();
  ProxyServer server(runtime);
  std::thread proxy_thread([&]() { server.run(); });
  if (!wait_for_port(port)) { proxy_thread.detach(); return expect(false, "connect_tunnel: proxy not ready"); }

  // CONNECT 到可达的上游（mock 服务器）
  MockUpstream upstream;
  if (!upstream.start_and_wait(18193)) { proxy_thread.detach(); return expect(false, "connect_tunnel: upstream not ready"); }

  std::ostringstream req;
  req << "CONNECT 127.0.0.1:" << upstream.port << " HTTP/1.1\r\n"
      << "Host: 127.0.0.1:" << upstream.port << "\r\n\r\n";

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct timeval tv{}; tv.tv_sec = 5;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd); proxy_thread.detach(); upstream.stop();
    return expect(false, "connect_tunnel: connect to proxy failed");
  }
  if (send(fd, req.str().data(), req.str().size(), 0) <= 0) {
    close(fd); proxy_thread.detach(); upstream.stop();
    return expect(false, "connect_tunnel: send failed");
  }

  char buf[8192];
  std::string response;
  while (response.find("\r\n\r\n") == std::string::npos) {
    auto n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  close(fd);
  proxy_thread.detach();
  upstream.stop();

  if (response.empty()) return expect(false, "connect_tunnel: no response");
  bool ok = expect(response.find("200") != std::string::npos, "connect_tunnel: should contain 200");
  ok = expect(response.find("Connection Established") != std::string::npos, "connect_tunnel: should contain Connection Established") && ok;
  return ok;
}

}  // namespace

int main() {
  bool ok = true;
  std::cout << "Running integration tests...\n\n";

  ok = test_http_get_no_auth() && ok;
  ok = test_http_post_with_body() && ok;
  ok = test_basic_auth_no_creds() && ok;
  ok = test_basic_auth_bad_creds() && ok;
  ok = test_basic_auth_valid_creds() && ok;
  ok = test_domain_blacklist_block() && ok;
  ok = test_url_blacklist_block() && ok;
  ok = test_domain_whitelist_allow() && ok;
  ok = test_default_block_non_whitelisted() && ok;
  ok = test_blacklist_over_whitelist() && ok;
  ok = test_portal_redirect_browser() && ok;
  ok = test_portal_no_redirect_for_script() && ok;
  ok = test_portal_cookie_valid() && ok;
  ok = test_portal_cookie_expired() && ok;
  ok = test_auth_pass_policy_block() && ok;
  ok = test_connect_auth_required() && ok;
  ok = test_connect_tunnel_no_mitm() && ok;

  std::cout << "\n";
  if (ok) {
    std::cout << "All integration tests passed\n";
    return 0;
  }
  return 1;
}