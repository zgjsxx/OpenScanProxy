#include "openscanproxy/proxy/proxy_server.hpp"

#include "openscanproxy/core/util.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <sstream>
#include <thread>

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
  runtime_.stats.inc_total_requests();
  char buf[1024 * 1024];
  auto n = recv(cfd, buf, sizeof(buf), 0);
  if (n <= 0) {
    close(cfd);
    return;
  }
  std::string raw(buf, n);
  auto line_end = raw.find("\r\n");
  auto first = raw.substr(0, line_end);
  std::istringstream fl(first);
  std::string method, target;
  fl >> method >> target;

  if (method == "CONNECT") {
    handle_connect_tunnel(cfd, target, client_addr);
  } else {
    handle_http_forward(cfd, client_addr, raw);
  }
  close(cfd);
}

void ProxyServer::handle_connect_tunnel(int cfd, const std::string& target, const std::string&) {
  auto [host, port] = split_host_port(target, 443);
  int sfd = connect_host_port(host, port);
  if (sfd < 0) {
    std::string fail = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nbad gateway";
    send(cfd, fail.data(), fail.size(), 0);
    return;
  }

  std::string ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
  send(cfd, ok.data(), ok.size(), 0);

  if (!runtime_.config.enable_https_mitm) {
    relay_bidirectional(cfd, sfd);
    close(sfd);
    return;
  }

  runtime_.stats.inc_https_mitm_requests();
  handle_connect_mitm(cfd, sfd, host);
}

void ProxyServer::handle_connect_mitm(int cfd, int sfd, const std::string& host) {
  SSL* client_ssl = SSL_new(runtime_.tls_mitm.client_ctx());
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

void ProxyServer::handle_http_forward(int cfd, const std::string& client_addr, const std::string& raw) {
  http::HttpRequest req;
  if (!http::parse_request(raw, req)) return;

  auto host_h = http::header_get(req.headers, "Host");
  if (host_h.empty()) return;
  auto [host, port] = split_host_port(host_h, 80);

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

    runtime_.audit.write(audit::AuditEvent{core::now_iso8601(), client_addr, host, req.uri, req.method, false, f.filename,
                                           f.bytes.size(), f.mime, sha, result.scanner_name,
                                           policy::to_string(result.status), result.signature,
                                           policy::to_string(action)});

    if (action == core::Action::Block) {
      std::string body = "<html><body><h1>Blocked by OpenScanProxy</h1><p>Threat: " + result.signature + "</p></body></html>";
      std::ostringstream os;
      os << "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
      auto r = os.str();
      send(cfd, r.data(), r.size(), 0);
      return;
    }
  }

  int sfd = connect_host_port(host, port);
  if (sfd < 0) return;
  send(sfd, raw.data(), raw.size(), 0);

  std::string upstream;
  char b[1024 * 1024];
  auto n = recv(sfd, b, sizeof(b), 0);
  if (n > 0) upstream.assign(b, n);
  close(sfd);

  http::HttpResponse resp;
  if (http::parse_response(upstream, resp)) {
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
      if (action == core::Action::Block) {
        runtime_.stats.inc_blocked();
        std::string body = "<html><body><h1>Download Blocked</h1><p>Threat: " + result.signature + "</p></body></html>";
        std::ostringstream os;
        os << "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
        auto r = os.str();
        send(cfd, r.data(), r.size(), 0);
        return;
      }
      runtime_.audit.write(audit::AuditEvent{core::now_iso8601(), client_addr, host, req.uri, req.method, false, f.filename,
                                             f.bytes.size(), f.mime, sha, result.scanner_name,
                                             policy::to_string(result.status), result.signature,
                                             policy::to_string(action)});
    }
  }

  send(cfd, upstream.data(), upstream.size(), 0);
}

}  // namespace openscanproxy::proxy
