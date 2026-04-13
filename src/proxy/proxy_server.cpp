#include "openscanproxy/proxy/proxy_server.hpp"

#include "openscanproxy/core/logger.hpp"
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
#include <cctype>
#include <map>
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

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

audit::AuditEvent make_access_event(const std::string& timestamp, const std::string& client_addr, const std::string& host,
                                    const std::string& url, const std::string& method, int status_code,
                                    std::uint64_t latency_ms, std::size_t bytes_in, std::size_t bytes_out,
                                    bool https_mitm, const std::string& user) {
  const auto audit_user = user.empty() ? "-" : user;
  audit::AuditEvent event;
  event.event_type = "access";
  event.timestamp = timestamp;
  event.client_addr = client_addr;
  event.user = audit_user;
  event.host = host;
  event.url = url;
  event.url_category = policy::classify_url(host, url);
  event.method = method;
  event.status_code = status_code;
  event.latency_ms = latency_ms;
  event.bytes_in = bytes_in;
  event.bytes_out = bytes_out;
  event.https_mitm = https_mitm;
  event.action = status_code >= 400 ? "error" : "allow";
  return event;
}

audit::AuditEvent make_proxy_auth_event(const std::string& client_addr, const std::string& host, const std::string& url,
                                        const std::string& user, const std::string& action,
                                        const std::string& decision_source, const std::string& rule_hit = "") {
  audit::AuditEvent event;
  event.event_type = "auth";
  event.timestamp = core::now_iso8601();
  event.client_addr = client_addr;
  event.user = user.empty() ? "-" : user;
  event.host = host;
  event.url = url;
  event.action = action;
  event.decision_source = decision_source;
  event.rule_hit = rule_hit;
  return event;
}

std::string html_escape(const std::string& in);

std::string make_proxy_auth_required_response() {
  static const std::string body = "<html><body><h1>407 Proxy Authentication Required</h1></body></html>";
  std::ostringstream os;
  os << "HTTP/1.1 407 Proxy Authentication Required\r\n"
     << "Proxy-Authenticate: Basic realm=\"OpenScanProxy\"\r\n"
     << "Content-Type: text/html\r\n"
     << "Content-Length: " << body.size() << "\r\n\r\n"
     << body;
  return os.str();
}

std::string url_encode(const std::string& value) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[(c >> 4) & 0xF]);
      out.push_back(kHex[c & 0xF]);
    }
  }
  return out;
}

std::string url_decode(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      try {
        auto v = static_cast<char>(std::stoi(value.substr(i + 1, 2), nullptr, 16));
        out.push_back(v);
        i += 2;
        continue;
      } catch (...) {
      }
    }
    out.push_back(value[i] == '+' ? ' ' : value[i]);
  }
  return out;
}

std::map<std::string, std::string> parse_query_string(const std::string& text) {
  std::map<std::string, std::string> out;
  for (const auto& seg : core::split(text, '&')) {
    auto eq = seg.find('=');
    if (eq == std::string::npos) continue;
    out[url_decode(seg.substr(0, eq))] = url_decode(seg.substr(eq + 1));
  }
  return out;
}

std::map<std::string, std::string> parse_cookie_header(const std::string& cookie_header) {
  std::map<std::string, std::string> out;
  for (const auto& seg : core::split(cookie_header, ';')) {
    auto eq = seg.find('=');
    if (eq == std::string::npos) continue;
    out[core::trim(seg.substr(0, eq))] = core::trim(seg.substr(eq + 1));
  }
  return out;
}

std::string portal_login_url(const proxy::Runtime& runtime, const std::string& return_to) {
  return "https://" + runtime.config.proxy_auth_portal_listen_host + ":" +
         std::to_string(runtime.config.proxy_auth_portal_listen_port) + "/login?return_to=" + url_encode(return_to);
}

bool browser_like_request(const std::map<std::string, std::string>& headers) {
  auto ua = http::header_get(headers, "User-Agent");
  auto accept = lower(http::header_get(headers, "Accept"));
  return !ua.empty() && (accept.empty() || accept.find("text/html") != std::string::npos || accept.find("*/*") != std::string::npos);
}

std::string absolute_request_url(const std::string& host, const std::string& uri, bool https) {
  if (uri.rfind("http://", 0) == 0 || uri.rfind("https://", 0) == 0) return uri;
  auto path = uri.empty() ? "/" : uri;
  return std::string(https ? "https://" : "http://") + host + path;
}

std::string extract_host_from_absolute_url(const std::string& url) {
  auto scheme = url.find("://");
  if (scheme == std::string::npos) return "";
  auto start = scheme + 3;
  auto end = url.find_first_of("/?#", start);
  auto authority = url.substr(start, end == std::string::npos ? std::string::npos : end - start);
  auto at = authority.rfind('@');
  if (at != std::string::npos) authority = authority.substr(at + 1);
  auto colon = authority.find(':');
  return lower(colon == std::string::npos ? authority : authority.substr(0, colon));
}

std::string append_auth_token_to_url(const std::string& url, const std::string& token) {
  auto hash = url.find('#');
  auto base = hash == std::string::npos ? url : url.substr(0, hash);
  auto fragment = hash == std::string::npos ? "" : url.substr(hash);
  auto sep = base.find('?') == std::string::npos ? '?' : '&';
  return base + sep + "__osp_auth=" + url_encode(token) + fragment;
}

std::string strip_auth_token_from_url(const std::string& url) {
  auto hash = url.find('#');
  auto base = hash == std::string::npos ? url : url.substr(0, hash);
  auto fragment = hash == std::string::npos ? "" : url.substr(hash);
  auto query_pos = base.find('?');
  if (query_pos == std::string::npos) return url;
  auto prefix = base.substr(0, query_pos);
  auto query = base.substr(query_pos + 1);
  auto parts = core::split(query, '&');
  std::vector<std::string> kept;
  for (const auto& part : parts) {
    auto eq = part.find('=');
    auto key = url_decode(eq == std::string::npos ? part : part.substr(0, eq));
    if (key == "__osp_auth") continue;
    if (!part.empty()) kept.push_back(part);
  }
  std::ostringstream os;
  os << prefix;
  if (!kept.empty()) {
    os << '?';
    for (std::size_t i = 0; i < kept.size(); ++i) {
      if (i) os << '&';
      os << kept[i];
    }
  }
  os << fragment;
  return os.str();
}

std::string to_origin_form_uri(const std::string& uri) {
  if (uri.rfind("http://", 0) != 0 && uri.rfind("https://", 0) != 0) return uri;
  auto scheme = uri.find("://");
  auto path_begin = uri.find('/', scheme == std::string::npos ? 0 : scheme + 3);
  if (path_begin == std::string::npos) return "/";
  return uri.substr(path_begin);
}

std::string extract_auth_token_from_url(const std::string& url) {
  auto query_pos = url.find('?');
  if (query_pos == std::string::npos) return "";
  auto fragment_pos = url.find('#', query_pos + 1);
  auto query = url.substr(query_pos + 1, fragment_pos == std::string::npos ? std::string::npos : fragment_pos - query_pos - 1);
  auto params = parse_query_string(query);
  auto it = params.find("__osp_auth");
  return it == params.end() ? "" : it->second;
}

std::string make_redirect_response(const std::string& location, const std::string& extra_headers = "") {
  auto body = "<html><body><a href=\"" + html_escape(location) + "\">Redirecting</a></body></html>";
  std::ostringstream os;
  os << "HTTP/1.1 302 Found\r\n"
     << "Content-Type: text/html; charset=utf-8\r\n"
     << "Cache-Control: no-store\r\n"
     << "Location: " << location << "\r\n"
     << extra_headers
     << "Content-Length: " << body.size() << "\r\n\r\n"
     << body;
  return os.str();
}

std::string make_portal_redirect_response(const proxy::Runtime& runtime, const std::string& return_to) {
  return make_redirect_response(portal_login_url(runtime, return_to));
}

std::string make_domain_cookie_response(const proxy::Runtime& runtime, const std::string& absolute_url,
                                        const std::string& host, const std::string& username, bool secure_cookie) {
  auto cookie_value = runtime.build_proxy_auth_cookie_value(username, host);
  auto location = strip_auth_token_from_url(absolute_url);
  auto max_age = std::to_string(runtime.config.proxy_auth_portal_session_ttl_sec);
  auto cookie = "Set-Cookie: " + runtime.config.proxy_auth_cookie_name + "=" + cookie_value +
                "; HttpOnly; Path=/; Max-Age=" + max_age + (secure_cookie ? "; Secure" : "") + "\r\n";
  return make_redirect_response(location, cookie);
}

bool target_is_portal_endpoint(const proxy::Runtime& runtime, const std::string& host, std::uint16_t port) {
  return lower(host) == lower(runtime.config.proxy_auth_portal_listen_host) &&
         port == runtime.config.proxy_auth_portal_listen_port;
}

std::string html_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string make_block_notification_response(const std::string& reason, const std::string& matched_rule = "",
                                             const std::string& matched_type = "") {
  auto escaped_reason = html_escape(reason.empty() ? "Blocked by access policy" : reason);
  auto escaped_rule = html_escape(matched_rule);
  auto escaped_type = html_escape(matched_type);
  std::ostringstream body;
  body << "<!doctype html><html><head><meta charset=\"utf-8\">"
       << "<title>Access Blocked</title>"
       << "<style>"
       << "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;"
       << "margin:0;background:#f6f8fb;color:#1e293b;display:flex;justify-content:center;align-items:center;min-height:100vh;}"
       << ".card{max-width:680px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;"
       << "box-shadow:0 10px 30px rgba(15,23,42,.08);}"
       << "h1{margin:0 0 8px;color:#b91c1c;font-size:28px;}h2{margin:0 0 14px;font-size:18px;color:#334155;}"
       << ".reason{padding:12px 14px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;color:#991b1b;}"
       << ".meta{margin-top:10px;padding:12px 14px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;color:#334155;}"
       << ".meta strong{color:#0f172a;}"
       << ".meta-row{margin-top:6px;word-break:break-word;}"
       << ".meta-row:first-child{margin-top:0;}"
       << ".hint{margin-top:12px;color:#64748b;font-size:14px;}"
       << "</style></head><body><div class=\"card\"><h1>403 Access Blocked</h1>"
       << "<h2>OpenScanProxy 拦截了当前请求</h2>"
       << "<div class=\"reason\"><strong>Reason:</strong> " << escaped_reason << "</div>";
  if (!matched_rule.empty() || !matched_type.empty()) {
    body << "<div class=\"meta\">";
    if (!matched_rule.empty()) {
      body << "<div class=\"meta-row\"><strong>Matched Rule:</strong> " << escaped_rule << "</div>";
    }
    if (!matched_type.empty()) {
      body << "<div class=\"meta-row\"><strong>Decision Source:</strong> " << escaped_type << "</div>";
    }
    body << "</div>";
  }
  body << "<div class=\"hint\">如果你认为这是误拦截，请联系管理员并提供该页面截图。</div>"
       << "</div></body></html>";
  auto body_s = body.str();
  std::ostringstream os;
  os << "HTTP/1.1 403 Forbidden\r\n"
     << "Content-Type: text/html; charset=utf-8\r\n"
     << "Cache-Control: no-store\r\n"
     << "Content-Length: " << body_s.size() << "\r\n\r\n"
     << body_s;
  return os.str();
}

std::string format_request_headers_for_debug(const std::string& method, const std::string& target,
                                             const std::map<std::string, std::string>& headers) {
  std::ostringstream os;
  os << "request " << method << " " << target << " headers={";
  bool first = true;
  for (const auto& [k, v] : headers) {
    if (!first) os << ", ";
    first = false;
    auto key_lower = core::to_lower(k);
    if (key_lower == "authorization" || key_lower == "proxy-authorization" || key_lower == "cookie") {
      os << k << ":***";
    } else {
      os << k << ":" << v;
    }
  }
  os << "}";
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

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

bool base64_decode(const std::string& input, std::string& out) {
  out.clear();
  int val = 0;
  int valb = -8;
  for (unsigned char c : input) {
    if (std::isspace(c)) continue;
    if (c == '=') break;
    int d = base64_value(static_cast<char>(c));
    if (d < 0) return false;
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return true;
}

std::string sanitize_identity(std::string value) {
  value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
    return c < 0x20 || c == 0x7f;
  }), value.end());
  return core::trim(value);
}

std::string authenticate_proxy_request(const ProxyAuthStore& auth_store, const std::map<std::string, std::string>& headers) {
  if (!auth_store.enabled()) return "";
  auto auth = http::header_get(headers, "Proxy-Authorization");
  if (auth.empty()) return "";
  constexpr const char* prefix = "Basic ";
  if (auth.rfind(prefix, 0) != 0) return "";
  std::string decoded;
  if (!base64_decode(auth.substr(std::strlen(prefix)), decoded)) return "";
  auto pos = decoded.find(':');
  if (pos == std::string::npos) return "";
  auto user = sanitize_identity(decoded.substr(0, pos));
  auto password = decoded.substr(pos + 1);
  if (user.empty()) return "";
  if (!auth_store.authenticate(user, password)) return "";
  return user;
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

bool ssl_write_all(SSL* ssl, const char* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
    int n = SSL_write(ssl, data + sent, static_cast<int>(size - sent));
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool ssl_read_http_message(SSL* ssl, std::string& pending, std::string& raw_message) {
  raw_message.clear();
  char buf[8192];
  while (pending.find("\r\n\r\n") == std::string::npos) {
    auto n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) return false;
    pending.append(buf, static_cast<std::size_t>(n));
  }

  auto header_end = pending.find("\r\n\r\n");
  auto line_end = pending.find("\r\n");
  if (line_end == std::string::npos || line_end > header_end) return false;

  std::size_t content_length = 0;
  std::map<std::string, std::string> headers;
  std::istringstream hs(pending.substr(line_end + 2, header_end - line_end - 2));
  std::string hline;
  while (std::getline(hs, hline)) {
    if (!hline.empty() && hline.back() == '\r') hline.pop_back();
    if (hline.empty()) continue;
    auto pos = hline.find(':');
    if (pos == std::string::npos) return false;
    headers[core::trim(hline.substr(0, pos))] = core::trim(hline.substr(pos + 1));
  }

  auto chunked = has_chunked_encoding(headers);
  if (!chunked && !parse_content_length_header(headers, content_length)) return false;

  if (chunked) {
    while (pending.find("\r\n0\r\n\r\n", header_end + 4) == std::string::npos) {
      auto n = SSL_read(ssl, buf, sizeof(buf));
      if (n <= 0) return false;
      pending.append(buf, static_cast<std::size_t>(n));
    }
    auto msg_end = pending.find("\r\n0\r\n\r\n", header_end + 4);
    msg_end += 7;
    raw_message = pending.substr(0, msg_end);
    pending.erase(0, msg_end);
    return true;
  }

  auto expected = header_end + 4 + content_length;
  while (pending.size() < expected) {
    auto n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) return false;
    pending.append(buf, static_cast<std::size_t>(n));
  }

  raw_message = pending.substr(0, expected);
  pending.erase(0, expected);
  return true;
}

}  // namespace

void ProxyServer::run() {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    core::app_logger().log(core::LogLevel::Error, "proxy: socket() failed");
    return;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.proxy_listen_port);
  inet_pton(AF_INET, runtime_.config.proxy_listen_host.c_str(), &addr.sin_addr);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    core::app_logger().log(core::LogLevel::Error,
                           "proxy: bind() failed on " + runtime_.config.proxy_listen_host + ":" +
                               std::to_string(runtime_.config.proxy_listen_port));
    close(fd);
    return;
  }
  if (listen(fd, 128) != 0) {
    core::app_logger().log(core::LogLevel::Error, "proxy: listen() failed");
    close(fd);
    return;
  }
  core::app_logger().log(core::LogLevel::Info,
                         "proxy listening on " + runtime_.config.proxy_listen_host + ":" +
                             std::to_string(runtime_.config.proxy_listen_port));

  while (true) {
    sockaddr_in caddr{};
    socklen_t len = sizeof(caddr);
    int cfd = accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
    if (cfd < 0) continue;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
    std::string client_addr = std::string(ip) + ":" + std::to_string(ntohs(caddr.sin_port));
    std::thread([this, cfd, client_addr]() {
      try {
        handle_client(cfd, client_addr);
      } catch (const std::exception& ex) {
        core::app_logger().log(core::LogLevel::Error,
                               "proxy: unhandled client error from " + client_addr + ": " + ex.what());
        close(cfd);
      } catch (...) {
        core::app_logger().log(core::LogLevel::Error, "proxy: unknown client error from " + client_addr);
        close(cfd);
      }
    }).detach();
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
    if (core::app_logger().should_log(core::LogLevel::Debug)) {
      core::app_logger().log(core::LogLevel::Debug, format_request_headers_for_debug(method, target, headers));
    }
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

    auto user = authenticate_proxy_request(runtime_.proxy_auth, headers);
    if (runtime_.proxy_auth.enabled() && runtime_.config.proxy_auth_mode == "basic" && user.empty()) {
      auto start = std::chrono::steady_clock::now();
      auto response = make_proxy_auth_required_response();
      send(cfd, response.data(), response.size(), 0);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
      auto denied = make_access_event(core::now_iso8601(), client_addr, "", target, method, 407, ms, raw.size(), response.size(),
                                      false, "");
      denied.action = "block";
      denied.decision_source = "proxy_auth";
      denied.rule_hit = "missing_or_invalid_proxy_auth";
      runtime_.audit.write(denied);
      break;
    }

    runtime_.stats.inc_total_requests();
    if (method == "CONNECT") {
      handle_connect_tunnel(cfd, target, client_addr, user);
      break;
    }
    if (!handle_http_forward(cfd, client_addr, user, raw)) break;
    if (!pending.empty()) continue;
  }
  close(cfd);
}

void ProxyServer::handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr, const std::string& user) {
  auto start = std::chrono::steady_clock::now();
  auto [host, port] = split_host_port(target, 443);
  if (runtime_.config.enable_proxy_auth && user.empty() && !runtime_.config.enable_https_mitm) {
    auto response = make_proxy_auth_required_response();
    send(cfd, response.data(), response.size(), 0);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto denied = make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 407, ms, 0, response.size(), false, "");
    denied.action = "block";
    denied.decision_source = "proxy_basic_fallback";
    denied.rule_hit = "missing_proxy_auth_for_connect";
    runtime_.audit.write(denied);
    return;
  }
  auto access = runtime_.policy.evaluate_access(host, target, "CONNECT", user);
  if (access.action == policy::AccessAction::Block && !runtime_.config.enable_https_mitm) {
    auto r = make_block_notification_response(access.reason, access.matched_rule, access.matched_type);
    send(cfd, r.data(), r.size(), 0);
    runtime_.stats.inc_blocked();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto event = make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 403, ms, 0, r.size(), false, user);
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
        make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 502, ms, 0, fail.size(), false, user));
    return;
  }

  std::string ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
  send(cfd, ok.data(), ok.size(), 0);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, target, "CONNECT", 200, ms, 0, ok.size(),
                                         runtime_.config.enable_https_mitm, user));

  if (!runtime_.config.enable_https_mitm) {
    relay_bidirectional(cfd, sfd);
    close(sfd);
    return;
  }

  runtime_.stats.inc_https_mitm_requests();
  handle_connect_mitm(cfd, sfd, host, client_addr, user);
}

void ProxyServer::handle_connect_mitm(int cfd, int sfd, const std::string& host, const std::string& client_addr, const std::string& user) {
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

  std::string client_pending;
  std::string upstream_pending;
  while (true) {
    std::string raw_req;
    if (!ssl_read_http_message(client_ssl, client_pending, raw_req)) break;

    http::HttpRequest req;
    if (!http::parse_request(raw_req, req)) break;
    auto resolved_user = user;
    const auto absolute_url = absolute_request_url(host, req.uri, true);
    if (runtime_.config.enable_proxy_auth) {
      auto cookies = parse_cookie_header(http::header_get(req.headers, "Cookie"));
      if (resolved_user.empty()) {
        auto cookie_it = cookies.find(runtime_.config.proxy_auth_cookie_name);
        if (cookie_it != cookies.end()) {
          resolved_user = runtime_.validate_proxy_auth_cookie(cookie_it->second, host);
          if (!resolved_user.empty()) {
            runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, resolved_user, "allow", "proxy_portal_cookie"));
          }
        }
      }
      if (resolved_user.empty() && runtime_.portal_auth_enabled()) {
        auto auth_token = extract_auth_token_from_url(req.uri);
        if (!auth_token.empty()) {
          auto token_user = runtime_.domain_tokens.consume(auth_token, host);
          if (!token_user.empty()) {
            auto response = make_domain_cookie_response(runtime_, absolute_url, host, token_user, true);
            ssl_write_all(client_ssl, response.data(), response.size());
            runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, token_user, "allow", "proxy_portal_token"));
            SSL_shutdown(client_ssl);
            SSL_shutdown(upstream_ssl);
            SSL_free(client_ssl);
            SSL_free(upstream_ssl);
            close(sfd);
            return;
          }
          auto response = make_block_notification_response("Invalid or expired authentication token");
          ssl_write_all(client_ssl, response.data(), response.size());
          runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "block", "proxy_portal_token",
                                                    "invalid_or_expired_token"));
          SSL_shutdown(client_ssl);
          SSL_shutdown(upstream_ssl);
          SSL_free(client_ssl);
          SSL_free(upstream_ssl);
          close(sfd);
          return;
        }
        auto response = make_portal_redirect_response(runtime_, absolute_url);
        ssl_write_all(client_ssl, response.data(), response.size());
        runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "redirect", "proxy_auth_portal"));
        SSL_shutdown(client_ssl);
        SSL_shutdown(upstream_ssl);
        SSL_free(client_ssl);
        SSL_free(upstream_ssl);
        close(sfd);
        return;
      }
      if (resolved_user.empty() && runtime_.proxy_basic_enabled()) {
        auto response = make_proxy_auth_required_response();
        ssl_write_all(client_ssl, response.data(), response.size());
        runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "block", "proxy_basic_fallback",
                                                  "missing_or_invalid_proxy_auth"));
        SSL_shutdown(client_ssl);
        SSL_shutdown(upstream_ssl);
        SSL_free(client_ssl);
        SSL_free(upstream_ssl);
        close(sfd);
        return;
      }
    }
    auto access = runtime_.policy.evaluate_access(host, req.uri, req.method, resolved_user);
    if (access.action == policy::AccessAction::Block) {
      auto r = make_block_notification_response(access.reason, access.matched_rule, access.matched_type);
      ssl_write_all(client_ssl, r.data(), r.size());
      runtime_.stats.inc_blocked();
      auto event = make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 403, 0, raw_req.size(), r.size(), true, resolved_user);
      event.action = "block";
      event.rule_hit = access.matched_rule;
      event.decision_source = access.matched_type;
      runtime_.audit.write(event);
      SSL_shutdown(client_ssl);
      SSL_shutdown(upstream_ssl);
      SSL_free(client_ssl);
      SSL_free(upstream_ssl);
      close(sfd);
      return;
    }

    for (auto& f : runtime_.extractor.from_request(req, host)) {
      if (f.bytes.size() > runtime_.config.max_scan_file_size) continue;
      auto result = runtime_.scanner->scan(f, runtime_.scan_ctx);
      auto action = runtime_.policy.decide(result);
      runtime_.stats.inc_scanned_files();
      if (result.status == core::ScanStatus::Clean) runtime_.stats.inc_clean();
      else if (result.status == core::ScanStatus::Infected) runtime_.stats.inc_infected();
      else if (result.status == core::ScanStatus::Suspicious) runtime_.stats.inc_suspicious();
      else runtime_.stats.inc_scanner_error();
      if (action == core::Action::Block) runtime_.stats.inc_blocked();

      audit::AuditEvent scan_event;
      scan_event.event_type = "scan";
      scan_event.timestamp = core::now_iso8601();
      scan_event.client_addr = client_addr;
      scan_event.user = resolved_user.empty() ? "-" : resolved_user;
      scan_event.host = host;
      scan_event.url = req.uri;
      scan_event.url_category = policy::classify_url(host, req.uri);
      scan_event.method = req.method;
      scan_event.filename = f.filename;
      scan_event.file_size = f.bytes.size();
      scan_event.mime = f.mime;
      scan_event.sha256 = core::sha256_hex(f.bytes);
      scan_event.scanner = result.scanner_name;
      scan_event.result = policy::to_string(result.status);
      scan_event.signature = result.signature;
      scan_event.action = policy::to_string(action);
      scan_event.rule_hit = result.signature;
      scan_event.decision_source = "policy_https_mitm_request";
      runtime_.audit.write(scan_event);

      if (action == core::Action::Block) {
        auto r = make_block_notification_response("Threat detected: " + result.signature);
        ssl_write_all(client_ssl, r.data(), r.size());
        SSL_shutdown(client_ssl);
        SSL_shutdown(upstream_ssl);
        SSL_free(client_ssl);
        SSL_free(upstream_ssl);
        close(sfd);
        return;
      }
    }

    if (!ssl_write_all(upstream_ssl, raw_req.data(), raw_req.size())) break;

    std::string raw_resp;
    if (!ssl_read_http_message(upstream_ssl, upstream_pending, raw_resp)) break;

    http::HttpResponse resp;
    if (http::parse_response(raw_resp, resp)) {
      for (auto& f : runtime_.extractor.from_response(req, resp, host)) {
        if (f.bytes.size() > runtime_.config.max_scan_file_size) continue;
        auto result = runtime_.scanner->scan(f, runtime_.scan_ctx);
        auto action = runtime_.policy.decide(result);
        runtime_.stats.inc_scanned_files();
        if (result.status == core::ScanStatus::Clean) runtime_.stats.inc_clean();
        else if (result.status == core::ScanStatus::Infected) runtime_.stats.inc_infected();
        else if (result.status == core::ScanStatus::Suspicious) runtime_.stats.inc_suspicious();
        else runtime_.stats.inc_scanner_error();
        if (action == core::Action::Block) runtime_.stats.inc_blocked();

        audit::AuditEvent scan_event;
        scan_event.event_type = "scan";
        scan_event.timestamp = core::now_iso8601();
        scan_event.client_addr = client_addr;
        scan_event.user = resolved_user.empty() ? "-" : resolved_user;
        scan_event.host = host;
        scan_event.url = req.uri;
        scan_event.url_category = policy::classify_url(host, req.uri);
        scan_event.method = req.method;
        scan_event.status_code = resp.status;
        scan_event.filename = f.filename;
        scan_event.file_size = f.bytes.size();
        scan_event.mime = f.mime;
        scan_event.sha256 = core::sha256_hex(f.bytes);
        scan_event.scanner = result.scanner_name;
        scan_event.result = policy::to_string(result.status);
        scan_event.signature = result.signature;
        scan_event.action = policy::to_string(action);
        scan_event.rule_hit = result.signature;
        scan_event.decision_source = "policy_https_mitm_response";
        runtime_.audit.write(scan_event);

        if (action == core::Action::Block) {
          auto r = make_block_notification_response("Threat detected: " + result.signature);
          ssl_write_all(client_ssl, r.data(), r.size());
          SSL_shutdown(client_ssl);
          SSL_shutdown(upstream_ssl);
          SSL_free(client_ssl);
          SSL_free(upstream_ssl);
          close(sfd);
          return;
        }
      }
    }

    if (!ssl_write_all(client_ssl, raw_resp.data(), raw_resp.size())) break;

    if (http::message_should_close(req.version, req.headers) || http::message_should_close(resp.version, resp.headers)) break;
  }

  SSL_shutdown(client_ssl);
  SSL_shutdown(upstream_ssl);
  SSL_free(client_ssl);
  SSL_free(upstream_ssl);
  close(sfd);
}

bool ProxyServer::handle_http_forward(int cfd, const std::string& client_addr, const std::string& user, const std::string& raw) {
  auto start = std::chrono::steady_clock::now();
  std::size_t bytes_in = raw.size();
  http::HttpRequest req;
  if (!http::parse_request(raw, req)) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, "", "", "", 400, ms, bytes_in, 0, false, user));
    return false;
  }

  auto host_h = http::header_get(req.headers, "Host");
  if (host_h.empty()) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, "", req.uri, req.method, 400, ms, bytes_in, 0, false, user));
    return false;
  }
  auto [host, port] = split_host_port(host_h, 80);
  auto resolved_user = user;
  const auto secure_cookie = false;
  const auto absolute_url = absolute_request_url(host_h, req.uri, false);
  const auto portal_target = target_is_portal_endpoint(runtime_, host, port);
  if (runtime_.config.enable_proxy_auth && !portal_target) {
    auto cookies = parse_cookie_header(http::header_get(req.headers, "Cookie"));
    if (resolved_user.empty()) {
      auto cookie_it = cookies.find(runtime_.config.proxy_auth_cookie_name);
      if (cookie_it != cookies.end()) {
        resolved_user = runtime_.validate_proxy_auth_cookie(cookie_it->second, host);
        if (!resolved_user.empty()) {
          runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, resolved_user, "allow", "proxy_portal_cookie"));
        }
      }
    }
    if (resolved_user.empty() && runtime_.portal_auth_enabled()) {
      auto auth_token = extract_auth_token_from_url(req.uri);
      if (!auth_token.empty()) {
        auto token_user = runtime_.domain_tokens.consume(auth_token, host);
        if (!token_user.empty()) {
          auto response = make_domain_cookie_response(runtime_, absolute_url, host, token_user, secure_cookie);
          send(cfd, response.data(), response.size(), 0);
          runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, token_user, "allow", "proxy_portal_token"));
          return false;
        }
        auto response = make_block_notification_response("Invalid or expired authentication token");
        send(cfd, response.data(), response.size(), 0);
        runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "block", "proxy_portal_token", "invalid_or_expired_token"));
        return false;
      }
      if (runtime_.config.proxy_auth_mode == "portal" || browser_like_request(req.headers)) {
        auto response = make_portal_redirect_response(runtime_, absolute_url);
        send(cfd, response.data(), response.size(), 0);
        runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "redirect", "proxy_auth_portal"));
        return false;
      }
    }
    if (resolved_user.empty() && runtime_.proxy_basic_enabled()) {
      auto response = make_proxy_auth_required_response();
      send(cfd, response.data(), response.size(), 0);
      runtime_.audit.write(make_proxy_auth_event(client_addr, host, absolute_url, "", "block", "proxy_basic_fallback",
                                                 "missing_or_invalid_proxy_auth"));
      return false;
    }
  }

  if (!portal_target) {
    auto access = runtime_.policy.evaluate_access(host, req.uri, req.method, resolved_user);
    if (access.action == policy::AccessAction::Block) {
      auto r = make_block_notification_response(access.reason, access.matched_rule, access.matched_type);
      send(cfd, r.data(), r.size(), 0);
      runtime_.stats.inc_blocked();
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
      auto event =
          make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 403, ms, bytes_in, r.size(), false, resolved_user);
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
      scan_event.user = resolved_user.empty() ? "-" : resolved_user;
      scan_event.host = host;
      scan_event.url = req.uri;
      scan_event.url_category = policy::classify_url(host, req.uri);
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
        auto r = make_block_notification_response("Threat detected: " + result.signature);
        send(cfd, r.data(), r.size(), 0);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 403, ms, bytes_in,
                                               r.size(), false, resolved_user));
        return false;
      }
    }
  }

  int sfd = connect_host_port(host, port);
  if (sfd < 0) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    runtime_.audit.write(make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, 502, ms, bytes_in, 0, false, resolved_user));
    return false;
  }
  req.headers.erase("Proxy-Authorization");
  req.headers.erase("proxy-authorization");
  req.uri = to_origin_form_uri(strip_auth_token_from_url(req.uri));
  auto forward_raw = http::serialize_request(req);
  if (!send_all(sfd, forward_raw.data(), forward_raw.size())) {
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
  if (!portal_target && http::parse_response(upstream, resp)) {
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
      scan_event.user = resolved_user.empty() ? "-" : resolved_user;
      scan_event.host = host;
      scan_event.url = req.uri;
      scan_event.url_category = policy::classify_url(host, req.uri);
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
      make_access_event(core::now_iso8601(), client_addr, host, req.uri, req.method, final_status, ms, bytes_in, bytes_out, false, resolved_user));
  return !http::message_should_close(req.version, req.headers) &&
         !(resp.version.empty() ? true : http::message_should_close(resp.version, resp.headers));
}

}  // namespace openscanproxy::proxy

