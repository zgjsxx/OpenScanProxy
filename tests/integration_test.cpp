#include "openscanproxy/config/config.hpp"
#include "openscanproxy/http/http_message.hpp"
#include "openscanproxy/policy/policy.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/proxy/runtime.hpp"
#include "openscanproxy/scanner/scanner.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using openscanproxy::config::AppConfig;
using openscanproxy::http::HttpRequest;
using openscanproxy::http::HttpResponse;
using openscanproxy::http::header_add;
using openscanproxy::http::header_get;
using openscanproxy::http::parse_request;
using openscanproxy::http::parse_response;
using openscanproxy::policy::AccessAction;
using openscanproxy::policy::PolicyConfig;
using openscanproxy::proxy::ProxyServer;
using openscanproxy::proxy::Runtime;

namespace {

bool expect(bool value, const std::string& message) {
  if (!value) std::cerr << "FAIL: " << message << "\n";
  return value;
}

std::string base64_encode(const std::string& input) {
  static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0;
  int valb = -6;
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

int reserve_loopback_port() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  socklen_t len = sizeof(addr);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
    close(fd);
    return -1;
  }
  int port = ntohs(addr.sin_port);
  close(fd);
  return port;
}

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
  std::thread thread;

  bool start(int desired_port) {
    port = desired_port;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return false;
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      close(listen_fd);
      listen_fd = -1;
      return false;
    }
    if (listen(listen_fd, 16) != 0) {
      close(listen_fd);
      listen_fd = -1;
      return false;
    }

    running = true;
    thread = std::thread([this]() { serve(); });
    return true;
  }

  void serve() {
    while (running) {
      sockaddr_in caddr{};
      socklen_t len = sizeof(caddr);
      int cfd = accept(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &len);
      if (cfd < 0) {
        if (!running) break;
        continue;
      }

      timeval tv{};
      tv.tv_sec = 3;
      tv.tv_usec = 0;
      setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

      std::string request;
      char buf[8192];
      while (request.find("\r\n\r\n") == std::string::npos) {
        auto n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        request.append(buf, static_cast<std::size_t>(n));
      }

      auto header_end = request.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        auto transfer_encoding_pos = request.find("Transfer-Encoding:");
        auto content_length_pos = request.find("Content-Length:");
        if (transfer_encoding_pos != std::string::npos &&
            request.find("chunked", transfer_encoding_pos) != std::string::npos) {
          while (request.find("\r\n0\r\n\r\n") == std::string::npos &&
                 request.find("\r\n0\r\n", header_end) == std::string::npos) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<std::size_t>(n));
          }
        } else if (content_length_pos != std::string::npos) {
          auto line_end = request.find("\r\n", content_length_pos);
          auto value = request.substr(content_length_pos + 15,
                                      line_end == std::string::npos ? std::string::npos : line_end - (content_length_pos + 15));
          std::size_t content_length = 0;
          try {
            content_length = static_cast<std::size_t>(std::stoull(value));
          } catch (...) {
            content_length = 0;
          }
          while (request.size() < header_end + 4 + content_length) {
            auto n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<std::size_t>(n));
          }
        }
      }

      {
        std::lock_guard<std::mutex> lock(mu);
        last_request = request;
      }

      std::ostringstream os;
      os << "HTTP/1.1 " << response_status << " " << response_reason << "\r\n"
         << "Content-Type: " << response_content_type << "\r\n"
         << "Content-Length: " << response_body.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << response_body;
      auto response = os.str();
      send(cfd, response.data(), response.size(), 0);
      close(cfd);
    }
  }

  std::string take_last_request() {
    std::lock_guard<std::mutex> lock(mu);
    return last_request;
  }

  void stop() {
    running = false;
    if (listen_fd >= 0) {
      shutdown(listen_fd, SHUT_RDWR);
      close(listen_fd);
      listen_fd = -1;
    }
    if (thread.joinable()) thread.join();
  }

  ~MockUpstreamServer() { stop(); }
};

struct TestProxyHarness {
  MockUpstreamServer upstream;
  std::unique_ptr<Runtime> runtime;
  std::unique_ptr<ProxyServer> proxy;
  std::thread proxy_thread;
  int proxy_port = -1;
  int upstream_port = -1;
  std::filesystem::path temp_dir;

  static AppConfig make_config(const std::filesystem::path& temp_dir, int proxy_port) {
    AppConfig cfg;
    cfg.proxy_listen_host = "127.0.0.1";
    cfg.proxy_listen_port = static_cast<uint16_t>(proxy_port);
    cfg.admin_listen_host = "127.0.0.1";
    cfg.admin_listen_port = 0;
    cfg.proxy_auth_signing_key = "integration-test-signing-key";
    cfg.proxy_auth_portal_listen_host = "127.0.0.1";
    cfg.proxy_auth_portal_listen_port = 29091;
    cfg.proxy_auth_portal_session_ttl_sec = 3600;
    cfg.scanner_type = "mock";
    cfg.app_log_level = "error";
    cfg.app_log_path = (temp_dir / "app.log").string();
    cfg.audit_log_path = (temp_dir / "audit.log").string();
    cfg.proxy_auth_portal_session_file = (temp_dir / "portal_sessions.json").string();
    cfg.proxy_auth_client_cache_file = (temp_dir / "portal_client_cache.json").string();
    cfg.tls_leaf_cache_enabled = false;
    cfg.ca_cert_path = "";
    cfg.ca_key_path = "";
    return cfg;
  }

  bool start(bool enable_auth = false, const std::string& auth_mode = "basic") {
    proxy_port = reserve_loopback_port();
    upstream_port = reserve_loopback_port();
    if (proxy_port <= 0 || upstream_port <= 0) return false;

    temp_dir = std::filesystem::temp_directory_path() /
               ("osp_integration_" + std::to_string(proxy_port) + "_" + std::to_string(upstream_port));
    std::filesystem::create_directories(temp_dir);

    if (!upstream.start(upstream_port)) return false;

    auto cfg = make_config(temp_dir, proxy_port);
    runtime = std::make_unique<Runtime>(cfg);
    runtime->scanner = openscanproxy::scanner::create_mock_scanner();
    if (enable_auth) {
      runtime->auth_enabled = true;
      runtime->auth_mode = auth_mode;
      runtime->proxy_auth.set_enabled(true);
      runtime->proxy_auth.add_user_direct("testuser", "testpass");
    }
    proxy = std::make_unique<ProxyServer>(*runtime);
    proxy_thread = std::thread([this]() { proxy->run(); });

    for (int i = 0; i < 100; ++i) {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) break;
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      addr.sin_port = htons(static_cast<uint16_t>(proxy_port));
      if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        close(fd);
        return true;
      }
      close(fd);
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }

  bool start_with_policy(const PolicyConfig& policy_cfg, bool enable_auth = false,
                         const std::string& auth_mode = "basic") {
    if (!start(enable_auth, auth_mode)) return false;
    runtime->policy.update(policy_cfg);
    return true;
  }

  std::string send_raw(const std::string& request) const {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";

    timeval tv{};
    tv.tv_sec = 5;
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
    if (send(fd, request.data(), request.size(), 0) <= 0) {
      close(fd);
      return "";
    }

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

  HttpResponse send_and_parse(const std::string& request) const {
    HttpResponse response;
    auto raw = send_raw(request);
    if (!raw.empty()) parse_response(raw, response);
    return response;
  }

  void stop() {
    if (proxy) proxy->stop();
    if (proxy_thread.joinable()) proxy_thread.join();
    upstream.stop();
    proxy.reset();
    runtime.reset();
    if (!temp_dir.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(temp_dir, ec);
    }
  }

  ~TestProxyHarness() { stop(); }
};

bool test_http_get_forward() {
  TestProxyHarness harness;
  if (!expect(harness.start(false), "http_get_forward: harness should start")) return false;

  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/test HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Connection: close\r\n\r\n";

  auto raw_response = harness.send_raw(request.str());
  if (!expect(!raw_response.empty(), "http_get_forward: proxy should return a response")) return false;

  HttpResponse response;
  if (!expect(parse_response(raw_response, response), "http_get_forward: response should be parseable")) return false;

  auto upstream_raw = harness.upstream.take_last_request();
  HttpRequest upstream_request;
  bool upstream_parsed = parse_request(upstream_raw, upstream_request);

  return expect(response.status == 200, "http_get_forward: status should be 200") &&
         expect(std::string(response.body.begin(), response.body.end()) == "upstream-ok",
                "http_get_forward: body should come from upstream") &&
         expect(upstream_parsed, "http_get_forward: upstream request should be parseable") &&
         expect(upstream_request.uri == "/test", "http_get_forward: proxy should forward origin-form URI") &&
         expect(header_get(upstream_request.headers, "Proxy-Authorization").empty(),
                "http_get_forward: proxy auth header should not leak upstream");
}

bool test_http_post_chunked_with_trailer() {
  TestProxyHarness harness;
  if (!expect(harness.start(false), "http_post_chunked_with_trailer: harness should start")) return false;

  std::ostringstream request;
  request << "POST http://127.0.0.1:" << harness.upstream_port << "/chunked HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Transfer-Encoding: chunked\r\n"
          << "Trailer: X-Digest\r\n"
          << "Connection: close\r\n\r\n"
          << "5\r\nhello\r\n"
          << "6\r\n world\r\n"
          << "0\r\n"
          << "X-Digest: sha256=abc123\r\n\r\n";

  auto raw_response = harness.send_raw(request.str());
  HttpResponse response;
  if (!expect(parse_response(raw_response, response), "http_post_chunked_with_trailer: response should parse")) return false;

  auto upstream_raw = harness.upstream.take_last_request();
  HttpRequest upstream_request;
  if (!expect(parse_request(upstream_raw, upstream_request),
              "http_post_chunked_with_trailer: upstream request should be parseable")) return false;

  return expect(response.status == 200, "http_post_chunked_with_trailer: status should be 200") &&
         expect(std::string(upstream_request.body.begin(), upstream_request.body.end()) == "hello world",
                "http_post_chunked_with_trailer: upstream body should decode to the expected payload") &&
         expect(header_get(upstream_request.trailers, "X-Digest") == "sha256=abc123",
                "http_post_chunked_with_trailer: upstream trailer should survive proxy forwarding");
}

bool test_basic_auth_valid() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "basic"), "basic_auth_valid: harness should start")) return false;

  auto credentials = base64_encode("testuser:testpass");
  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/auth HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Proxy-Authorization: Basic " << credentials << "\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  return expect(response.status == 200, "basic_auth_valid: status should be 200");
}

bool test_basic_auth_missing() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "basic"), "basic_auth_missing: harness should start")) return false;

  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/auth HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  return expect(response.status == 407, "basic_auth_missing: status should be 407");
}

bool test_portal_cookie_valid() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "portal"), "portal_cookie_valid: harness should start")) return false;

  auto cookie_value = harness.runtime->build_proxy_auth_cookie_value("portaluser", "127.0.0.1");
  auto cookie_name = harness.runtime->proxy_auth_cookie_name_for_scheme(false);
  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/portal HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Cookie: " << cookie_name << "=" << cookie_value << "\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  return expect(response.status == 200, "portal_cookie_valid: valid cookie should allow request");
}

bool test_portal_redirect_for_browser_navigation() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "portal"), "portal_redirect_for_browser_navigation: harness should start")) return false;

  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/page HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "User-Agent: Mozilla/5.0\r\n"
          << "Accept: text/html\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  auto location = header_get(response.headers, "Location");

  return expect(response.status == 302, "portal_redirect_for_browser_navigation: browser navigation should redirect") &&
         expect(location.find("/login") != std::string::npos,
                "portal_redirect_for_browser_navigation: redirect target should be portal login");
}

bool test_portal_script_request_is_rejected_not_redirected() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "portal"), "portal_script_request_is_rejected_not_redirected: harness should start")) return false;

  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/script.js HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "User-Agent: Mozilla/5.0\r\n"
          << "Sec-Fetch-Mode: no-cors\r\n"
          << "Sec-Fetch-Dest: script\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  auto location = header_get(response.headers, "Location");

  return expect(response.status == 403, "portal_script_request_is_rejected_not_redirected: script request should be rejected") &&
         expect(location.empty(), "portal_script_request_is_rejected_not_redirected: script request should not redirect");
}

bool test_domain_blacklist_blocks_after_auth() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Allow;
  policy_cfg.domain_blacklist = {"blocked.example.com"};

  TestProxyHarness harness;
  if (!expect(harness.start_with_policy(policy_cfg, true, "basic"),
              "domain_blacklist_blocks_after_auth: harness should start")) return false;

  auto credentials = base64_encode("testuser:testpass");
  std::ostringstream request;
  request << "GET http://blocked.example.com/test HTTP/1.1\r\n"
          << "Host: blocked.example.com\r\n"
          << "Proxy-Authorization: Basic " << credentials << "\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  return expect(response.status == 403, "domain_blacklist_blocks_after_auth: policy should still block after auth");
}

bool test_domain_whitelist_allows_when_default_block() {
  PolicyConfig policy_cfg;
  policy_cfg.default_access_action = AccessAction::Block;
  policy_cfg.domain_whitelist = {"127.0.0.1"};

  TestProxyHarness harness;
  if (!expect(harness.start_with_policy(policy_cfg, false),
              "domain_whitelist_allows_when_default_block: harness should start")) return false;

  std::ostringstream request;
  request << "GET http://127.0.0.1:" << harness.upstream_port << "/allowed HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n"
          << "Connection: close\r\n\r\n";

  auto response = harness.send_and_parse(request.str());
  return expect(response.status == 200, "domain_whitelist_allows_when_default_block: whitelisted host should pass");
}

bool test_connect_tunnel_without_mitm() {
  TestProxyHarness harness;
  if (!expect(harness.start(false), "connect_tunnel_without_mitm: harness should start")) return false;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (!expect(fd >= 0, "connect_tunnel_without_mitm: socket should be created")) return false;

  timeval tv{};
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(static_cast<uint16_t>(harness.proxy_port));
  if (!expect(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0,
              "connect_tunnel_without_mitm: should connect to proxy")) {
    close(fd);
    return false;
  }

  std::ostringstream request;
  request << "CONNECT 127.0.0.1:" << harness.upstream_port << " HTTP/1.1\r\n"
          << "Host: 127.0.0.1:" << harness.upstream_port << "\r\n\r\n";
  send(fd, request.str().data(), request.str().size(), 0);

  std::string response;
  char buf[8192];
  while (response.find("\r\n\r\n") == std::string::npos) {
    auto n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  close(fd);

  return expect(response.find("200 Connection Established") != std::string::npos,
                "connect_tunnel_without_mitm: proxy should establish CONNECT tunnel");
}

bool test_connect_requires_basic_auth() {
  TestProxyHarness harness;
  if (!expect(harness.start(true, "basic"), "connect_requires_basic_auth: harness should start")) return false;

  std::ostringstream request;
  request << "CONNECT example.com:443 HTTP/1.1\r\n"
          << "Host: example.com:443\r\n\r\n";

  auto raw_response = harness.send_raw(request.str());
  HttpResponse response;
  if (parse_response(raw_response, response)) {
    return expect(response.status == 407, "connect_requires_basic_auth: status should be 407");
  }
  return expect(raw_response.find("407") != std::string::npos,
                "connect_requires_basic_auth: raw response should mention 407");
}

}  // namespace

int main() {
  bool ok = true;
  std::cout << "Running proxy-level integration tests...\n";

  ok = test_http_get_forward() && ok;
  ok = test_http_post_chunked_with_trailer() && ok;
  ok = test_basic_auth_valid() && ok;
  ok = test_basic_auth_missing() && ok;
  ok = test_portal_cookie_valid() && ok;
  ok = test_portal_redirect_for_browser_navigation() && ok;
  ok = test_portal_script_request_is_rejected_not_redirected() && ok;
  ok = test_domain_blacklist_blocks_after_auth() && ok;
  ok = test_domain_whitelist_allows_when_default_block() && ok;
  ok = test_connect_tunnel_without_mitm() && ok;
  ok = test_connect_requires_basic_auth() && ok;

  if (ok) {
    std::cout << "All proxy-level integration tests passed\n";
    return 0;
  }
  return 1;
}

