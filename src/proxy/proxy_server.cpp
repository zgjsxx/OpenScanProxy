#include "openscanproxy/proxy/proxy_server.hpp"

#include "openscanproxy/core/util.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <chrono>
#include <algorithm>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

namespace openscanproxy::proxy {
namespace {
int connect_host_port(const std::string& host, uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return -1;
  int fd = -1;
  for (auto* p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

void relay_bidirectional(int a, int b) {
  auto f = [](int from, int to) {
    char buf[8192];
    while (true) {
      auto n = recv(from, buf, sizeof(buf), 0);
      if (n <= 0) break;
      if (send(to, buf, n, 0) <= 0) break;
    }
    shutdown(to, SHUT_WR);
  };
  std::thread t1(f, a, b), t2(f, b, a);
  t1.join();
  t2.join();
}

std::pair<std::string, uint16_t> split_host_port(const std::string& hp, uint16_t def_port) {
  auto pos = hp.find(':');
  if (pos == std::string::npos) return {hp, def_port};
  return {hp.substr(0, pos), static_cast<uint16_t>(std::stoi(hp.substr(pos + 1)))};
}

audit::AuditEvent make_access_event(const std::string& timestamp, const std::string& client_addr, const std::string& host,
                                    const std::string& url, const std::string& method, int status_code,
                                    std::uint64_t latency_ms, std::size_t bytes_in, std::size_t bytes_out,
                                    bool https_mitm) {
  audit::AuditEvent event;
  event.event_type = "access";
  event.timestamp = timestamp;
  event.client_addr = client_addr;
  event.host = host;
  event.url = url;
  event.method = method;
  event.status_code = status_code;
  event.latency_ms = latency_ms;
  event.bytes_in = bytes_in;
  event.bytes_out = bytes_out;
  event.https_mitm = https_mitm;
  event.action = status_code >= 400 ? "error" : "allow";
  return event;
}

std::string make_forbidden_response(const std::string& message) {
  std::string body = "<html><body><h1>403 Forbidden</h1><p>" + message + "</p></body></html>";
  std::ostringstream os;
  os << "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
  return os.str();
}

bool send_all(int fd, const char* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
    auto n = send(fd, data + sent, size - sent, 0);
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool parse_content_length_header(const std::map<std::string, std::string>& headers, std::size_t& content_length) {
  auto raw = http::header_get(headers, "Content-Length");
  if (raw.empty()) {
    content_length = 0;
    return true;
  }
  std::uint64_t v = 0;
  std::istringstream is(raw);
  is >> v;
  if (!is || !is.eof()) return false;
  content_length = static_cast<std::size_t>(v);
  return true;
}

bool has_chunked_encoding(const std::map<std::string, std::string>& headers) {
  auto te = core::to_lower(http::header_get(headers, "Transfer-Encoding"));
  return te.find("chunked") != std::string::npos;
}

bool parse_response_head(const std::string& raw_head, std::string& version, int& status,
                         std::map<std::string, std::string>& headers) {
  headers.clear();
  auto line_end = raw_head.find("\r\n");
  if (line_end == std::string::npos) return false;
  std::istringstream sl(raw_head.substr(0, line_end));
  if (!(sl >> version >> status)) return false;
  std::istringstream hs(raw_head.substr(line_end + 2));
  std::string hline;
  while (std::getline(hs, hline)) {
    if (!hline.empty() && hline.back() == '\r') hline.pop_back();
    if (hline.empty()) continue;
    auto pos = hline.find(':');
    if (pos == std::string::npos) return false;
    headers[core::trim(hline.substr(0, pos))] = core::trim(hline.substr(pos + 1));
  }
  return true;
}

}  // namespace

void ProxyServer::run() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.proxy_listen_port);
  inet_pton(AF_INET, runtime_.config.proxy_listen_host.c_str(), &addr.sin_addr);
  bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  listen(fd, 128);

  while (true) {
    sockaddr_in caddr{};
    socklen_t len = sizeof(caddr);
    int cfd = accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
    if (cfd < 0) continue;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
    std::string client_addr = std::string(ip) + ":" + std::to_string(ntohs(caddr.sin_port));
    std::thread(&ProxyServer::handle_client, this, cfd, client_addr).detach();
  }
}

void ProxyServer::handle_client(int cfd, const std::string& client_addr) {
  std::string pending;
  char buf[8192];
  while (true) {
    while (pending.find("\r\n\r\n") == std::string::npos) {
      auto n = recv(cfd, buf, sizeof(buf), 0);
      if (n <= 0) {
        close(cfd);
        return;
      }
      pending.append(buf, static_cast<std::size_t>(n));
    }

    auto header_end = pending.find("\r\n\r\n");
    auto line_end = pending.find("\r\n");
    if (line_end == std::string::npos || line_end > header_end) break;

    std::string method;
    std::string target;
    std::string version;
    {
      std::istringstream fl(pending.substr(0, line_end));
      fl >> method >> target >> version;
    }
    if (method.empty()) break;

    std::size_t content_length = 0;
    std::map<std::string, std::string> headers;
    std::istringstream hs(pending.substr(line_end + 2, header_end - line_end - 2));
    std::string hline;
    while (std::getline(hs, hline)) {
      if (!hline.empty() && hline.back() == '\r') hline.pop_back();
      if (hline.empty()) continue;
      auto pos = hline.find(':');
      if (pos == std::string::npos) break;
      headers[core::trim(hline.substr(0, pos))] = core::trim(hline.substr(pos + 1));
    }
    auto is_chunked = has_chunked_encoding(headers);
    if (!is_chunked && !parse_content_length_header(headers, content_length)) break;

    if (is_chunked) {
      while (pending.find("\r\n0\r\n\r\n", header_end + 4) == std::string::npos) {
        auto n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        pending.append(buf, static_cast<std::size_t>(n));
      }
    } else {
      auto expected = header_end + 4 + content_length;
      while (pending.size() < expected) {
        auto n = recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        pending.append(buf, static_cast<std::size_t>(n));
      }
    }

    std::size_t consumed = pending.size();
    if (!is_chunked) consumed = header_end + 4 + content_length;
    auto raw = pending.substr(0, consumed);
    pending.erase(0, consumed);

    runtime_.stats.inc_total_requests();
    if (method == "CONNECT") {
      handle_connect_tunnel(cfd, target, client_addr);
      break;
    }
    if (!handle_http_forward(cfd, client_addr, raw)) break;
    if (!pending.empty()) continue;
  }
  close(cfd);
}

void ProxyServer::handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr) {
  auto start = std::chrono::steady_clock::now();
  auto [host, port] = split_host_port(target, 443);
  auto access = runtime_.policy.evaluate_access(host, target, "CONNECT");
  if (access.action == policy::AccessAction::Block) {
    auto r = make_forbidden_response("Blocked by access policy");
    send(cfd, r.data(), r.size(), 0);
    runtime_.stats.inc_blocked();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto event = make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 403, ms, 0, r.size(), false);
    event.action = "block";
    event.rule_hit = access.matched_rule;
    event.decision_source = access.matched_type;
    runtime_.audit.write(event);
    return;
  }

  int sfd = connect_host_port(host, port);
  if (sfd < 0) {
    std::string fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nbad gateway";
    send(cfd, fail.data(), fail.size(), 0);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(
        make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 502, ms, 0, fail.size(), false));
    return;
  }

  std::string ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
  send(cfd, ok.data(), ok.size(), 0);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 200, ms, 0, ok.size(),
                                         runtime_.config.enable_https_mitm));

  if (!runtime_.config.enable_https_mitm) {
    relay_bidirectional(cfd, sfd);
    close(sfd);
    return;
  }

  runtime_.stats.inc_https_mitm_requests();
  handle_connect_mitm(cfd, sfd, host);
}

void ProxyServer::handle_connect_mitm(int cfd, int sfd, const std::string& host) {
  std::unique_ptr<SSL_CTX, void (*)(SSL_CTX*)> host_ctx(runtime_.tls_mitm.create_server_ctx_for_host(host), SSL_CTX_free);
  if (!host_ctx) {
    close(sfd);
    return;
  }

  SSL* client_ssl = SSL_new(host_ctx.get());
  SSL* upstream_ssl = SSL_new(runtime_.tls_mitm.upstream_ctx());
  if (!client_ssl || !upstream_ssl) {
    if (client_ssl) SSL_free(client_ssl);
    if (upstream_ssl) SSL_free(upstream_ssl);
    close(sfd);
    return;
  }

  SSL_set_fd(client_ssl, cfd);
  SSL_set_fd(upstream_ssl, sfd);
  SSL_set_tlsext_host_name(upstream_ssl, host.c_str());

  if (SSL_accept(client_ssl) != 1 || SSL_connect(upstream_ssl) != 1) {
    SSL_shutdown(client_ssl);
    SSL_shutdown(upstream_ssl);
    SSL_free(client_ssl);
    SSL_free(upstream_ssl);
    close(sfd);
    return;
  }

  std::mutex write_lock_client;
  std::mutex write_lock_upstream;
  auto relay_tls = [&](SSL* from, SSL* to, std::mutex& write_lock) {
    char buf[8192];
    while (true) {
      int n = SSL_read(from, buf, sizeof(buf));
      if (n <= 0) break;
      int off = 0;
      while (off < n) {
        std::lock_guard<std::mutex> g(write_lock);
        int w = SSL_write(to, buf + off, n - off);
        if (w <= 0) return;
        off += w;
      }
    }
  };

  std::thread t1(relay_tls, client_ssl, upstream_ssl, std::ref(write_lock_upstream));
  std::thread t2(relay_tls, upstream_ssl, client_ssl, std::ref(write_lock_client));
  t1.join();
  t2.join();

  SSL_shutdown(client_ssl);
  SSL_shutdown(upstream_ssl);
  SSL_free(client_ssl);
  SSL_free(upstream_ssl);
  close(sfd);
}

bool ProxyServer::handle_http_forward(int cfd, const std::string& client_addr, const std::string& raw) {
  auto start = std::chrono::steady_clock::now();
  std::size_t bytes_in = raw.size();
  http::HttpRequest req;
  if (!http::parse_request(raw, req)) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, "", "", "", 400, ms, bytes_in, 0, false));
    return false;
  }

  auto host_h = http::header_get(req.headers, "Host");
  if (host_h.empty()) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, "", req.uri, req.method, 400, ms, bytes_in, 0, false));
    return false;
  }
  auto [host, port] = split_host_port(host_h, 80);
  auto access = runtime_.policy.evaluate_access(host, req.uri, req.method);
  if (access.action == policy::AccessAction::Block) {
    auto r = make_forbidden_response("Blocked by access policy");
    send(cfd, r.data(), r.size(), 0);
    runtime_.stats.inc_blocked();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto event =
        make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 403, ms, bytes_in, r.size(), false);
    event.action = "block";
    event.rule_hit = access.matched_rule;
    event.decision_source = access.matched_type;
    runtime_.audit.write(event);
    return false;
  }

  for (auto& f : runtime_.extractor.from_request(req, host)) {
    if (f.bytes.size() > runtime_.config.max_scan_file_size) continue;
    auto sha = core::sha256_hex(f.bytes);
    runtime_.stats.inc_scanned_files();
    auto result = runtime_.scanner->scan(f, runtime_.scan_ctx);
    if (result.status == core::ScanStatus::Clean) runtime_.stats.inc_clean();
    else if (result.status == core::ScanStatus::Infected) runtime_.stats.inc_infected();
    else if (result.status == core::ScanStatus::Suspicious) runtime_.stats.inc_suspicious();
    else runtime_.stats.inc_scanner_error();

    auto action = runtime_.policy.decide(result);
    if (action == core::Action::Block) runtime_.stats.inc_blocked();

    audit::AuditEvent scan_event;
    scan_event.event_type = "scan";
    scan_event.timestamp = core::now_iso8601();
    scan_event.client_addr = client_addr;
    scan_event.host = host;
    scan_event.url = req.uri;
    scan_event.method = req.method;
    scan_event.status_code = 0;
    scan_event.bytes_in = bytes_in;
    scan_event.filename = f.filename;
    scan_event.file_size = f.bytes.size();
    scan_event.mime = f.mime;
    scan_event.sha256 = sha;
    scan_event.scanner = result.scanner_name;
    scan_event.result = policy::to_string(result.status);
    scan_event.signature = result.signature;
    scan_event.action = policy::to_string(action);
    scan_event.rule_hit = result.signature;
    scan_event.decision_source = "policy";
    runtime_.audit.write(scan_event);

    if (action == core::Action::Block) {
      std::string body = "<html><body><h1>Blocked by OpenScanProxy</h1><p>Threat: " + result.signature + "</p></body></html>";
      std::ostringstream os;
      os << "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
      auto r = os.str();
      send(cfd, r.data(), r.size(), 0);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
      runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 403, ms, bytes_in,
                                             r.size(), false));
      return false;
    }
  }

  int sfd = connect_host_port(host, port);
  if (sfd < 0) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 502, ms, bytes_in, 0, false));
    return false;
  }
  if (!send_all(sfd, raw.data(), raw.size())) {
    close(sfd);
    return false;
  }

  std::string upstream_for_parse;
  upstream_for_parse.reserve(64 * 1024);
  std::size_t bytes_out = 0;
  int final_status = 502;
  bool parseable = true;
  std::size_t header_end = std::string::npos;
  std::size_t response_content_length = 0;
  bool response_chunked = false;
  bool response_close_delimited = false;
  bool should_stop = false;
  char b[8192];
  while (!should_stop) {
    auto n = recv(sfd, b, sizeof(b), 0);
    if (n <= 0) break;
    bytes_out += static_cast<std::size_t>(n);
    if (!send_all(cfd, b, static_cast<std::size_t>(n))) {
      close(sfd);
      return false;
    }
    if (parseable) upstream_for_parse.append(b, static_cast<std::size_t>(n));

    if (header_end == std::string::npos) {
      header_end = upstream_for_parse.find("\r\n\r\n");
      if (header_end != std::string::npos) {
        std::string response_version;
        std::map<std::string, std::string> response_headers;
        auto header_only = upstream_for_parse.substr(0, header_end + 2);
        if (!parse_response_head(header_only, response_version, final_status, response_headers)) {
          parseable = false;
        } else {
          response_chunked = has_chunked_encoding(response_headers);
          response_close_delimited = !response_chunked && http::header_get(response_headers, "Content-Length").empty();
          if (!response_chunked && !parse_content_length_header(response_headers, response_content_length)) parseable = false;
        }
      }
    }

    if (header_end != std::string::npos) {
      if (response_chunked) {
        if (upstream_for_parse.find("\r\n0\r\n\r\n", header_end + 4) != std::string::npos) should_stop = true;
      } else if (!response_close_delimited) {
        if (upstream_for_parse.size() >= header_end + 4 + response_content_length) should_stop = true;
      }
    }
    if (upstream_for_parse.size() > 4 * 1024 * 1024) parseable = false;
  }
  close(sfd);

  http::HttpResponse resp;
  std::string upstream = parseable ? upstream_for_parse : std::string{};
  if (http::parse_response(upstream, resp)) {
    final_status = resp.status;
    for (auto& f : runtime_.extractor.from_response(req, resp, host)) {
      if (f.bytes.size() > runtime_.config.max_scan_file_size) continue;
      auto sha = core::sha256_hex(f.bytes);
      runtime_.stats.inc_scanned_files();
      auto result = runtime_.scanner->scan(f, runtime_.scan_ctx);
      if (result.status == core::ScanStatus::Clean) runtime_.stats.inc_clean();
      else if (result.status == core::ScanStatus::Infected) runtime_.stats.inc_infected();
      else if (result.status == core::ScanStatus::Suspicious) runtime_.stats.inc_suspicious();
      else runtime_.stats.inc_scanner_error();

      auto action = runtime_.policy.decide(result);
      if (action == core::Action::Block) runtime_.stats.inc_blocked();
      audit::AuditEvent scan_event;
      scan_event.event_type = "scan";
      scan_event.timestamp = core::now_iso8601();
      scan_event.client_addr = client_addr;
      scan_event.host = host;
      scan_event.url = req.uri;
      scan_event.method = req.method;
      scan_event.status_code = resp.status;
      scan_event.bytes_in = bytes_in;
      scan_event.bytes_out = bytes_out;
      scan_event.filename = f.filename;
      scan_event.file_size = f.bytes.size();
      scan_event.mime = f.mime;
      scan_event.sha256 = sha;
      scan_event.scanner = result.scanner_name;
      scan_event.result = policy::to_string(result.status);
      scan_event.signature = result.signature;
      scan_event.action = policy::to_string(action);
      scan_event.rule_hit = result.signature;
      scan_event.decision_source = "policy";
      runtime_.audit.write(scan_event);
    }
  }
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  runtime_.audit.write(
      make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, final_status, ms, bytes_in, bytes_out, false));
  return !http::message_should_close(req.version, req.headers) &&
         !(resp.version.empty() ? true : http::message_should_close(resp.version, resp.headers));
}

}  // namespace openscanproxy::proxy
