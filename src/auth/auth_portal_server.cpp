#include "openscanproxy/auth/auth_portal_server.hpp"

#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/core/util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <memory>
#include <sstream>
#include <thread>

namespace openscanproxy::auth {
namespace {

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
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

bool read_http_message_over_ssl(SSL* ssl, std::string& raw_message) {
  raw_message.clear();
  std::string pending;
  char buf[8192];
  while (pending.find("\r\n\r\n") == std::string::npos) {
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) return false;
    pending.append(buf, static_cast<std::size_t>(n));
  }

  auto header_end = pending.find("\r\n\r\n");
  std::size_t content_length = 0;
  std::istringstream hs(pending.substr(0, header_end));
  std::string line;
  while (std::getline(hs, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto pos = line.find(':');
    if (pos == std::string::npos) continue;
    auto key = lower(core::trim(line.substr(0, pos)));
    auto value = core::trim(line.substr(pos + 1));
    if (key == "content-length") {
      try {
        content_length = static_cast<std::size_t>(std::stoull(value));
      } catch (...) {
        return false;
      }
    }
  }

  auto total_needed = header_end + 4 + content_length;
  while (pending.size() < total_needed) {
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n <= 0) return false;
    pending.append(buf, static_cast<std::size_t>(n));
  }

  raw_message = pending.substr(0, total_needed);
  return true;
}

std::string get_body(const std::string& req) {
  auto pos = req.find("\r\n\r\n");
  if (pos == std::string::npos) return "";
  return req.substr(pos + 4);
}

std::string get_header(const std::string& req, const std::string& key) {
  auto pos = req.find("\r\n" + key + ":");
  if (pos == std::string::npos) return "";
  auto line_begin = pos + 2 + key.size() + 1;
  while (line_begin < req.size() && req[line_begin] == ' ') ++line_begin;
  auto line_end = req.find("\r\n", line_begin);
  if (line_end == std::string::npos) return "";
  return req.substr(line_begin, line_end - line_begin);
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
        auto part = value.substr(i + 1, 2);
        auto v = static_cast<char>(std::stoi(part, nullptr, 16));
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

std::map<std::string, std::string> parse_form(const std::string& body) {
  std::map<std::string, std::string> out;
  for (const auto& seg : core::split(body, '&')) {
    auto eq = seg.find('=');
    if (eq == std::string::npos) continue;
    out[url_decode(seg.substr(0, eq))] = url_decode(seg.substr(eq + 1));
  }
  return out;
}

std::map<std::string, std::string> parse_query(const std::string& path) {
  std::map<std::string, std::string> out;
  auto pos = path.find('?');
  if (pos == std::string::npos) return out;
  for (const auto& seg : core::split(path.substr(pos + 1), '&')) {
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

std::string extract_host_from_url(const std::string& url) {
  auto scheme_pos = url.find("://");
  if (scheme_pos == std::string::npos) return "";
  auto host_begin = scheme_pos + 3;
  auto host_end = url.find_first_of("/?#", host_begin);
  auto authority = url.substr(host_begin, host_end == std::string::npos ? std::string::npos : host_end - host_begin);
  auto at = authority.rfind('@');
  if (at != std::string::npos) authority = authority.substr(at + 1);
  auto colon = authority.find(':');
  return lower(colon == std::string::npos ? authority : authority.substr(0, colon));
}

bool valid_return_to(const proxy::Runtime& runtime, const std::string& return_to) {
  if (return_to.empty()) return false;
  auto lower_url = lower(return_to);
  if (lower_url.rfind("http://", 0) != 0 && lower_url.rfind("https://", 0) != 0) return false;
  auto host = extract_host_from_url(return_to);
  if (host.empty()) return false;
  auto portal_host = lower(runtime.config.proxy_auth_portal_listen_host);
  if (host == portal_host && return_to.find(std::to_string(runtime.config.proxy_auth_portal_listen_port)) != std::string::npos) {
    return false;
  }
  return true;
}

std::string append_auth_token(const std::string& return_to, const std::string& token) {
  auto hash = return_to.find('#');
  auto base = hash == std::string::npos ? return_to : return_to.substr(0, hash);
  auto fragment = hash == std::string::npos ? "" : return_to.substr(hash);
  auto sep = base.find('?') == std::string::npos ? '?' : '&';
  return base + sep + "__osp_auth=" + url_encode(token) + fragment;
}

std::string make_http_response(int status, const std::string& reason, const std::string& body,
                               const std::string& ct = "text/html; charset=utf-8", const std::string& extra_headers = "") {
  std::ostringstream os;
  os << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
     << "Content-Type: " << ct << "\r\n"
     << "Cache-Control: no-store\r\n"
     << "Content-Length: " << body.size() << "\r\n"
     << extra_headers
     << "Connection: close\r\n\r\n"
     << body;
  return os.str();
}

std::string redirect_response(const std::string& location, const std::string& extra_headers = "") {
  std::string body = "<html><body><a href=\"" + html_escape(location) + "\">Redirecting</a></body></html>";
  return make_http_response(302, "Found", body, "text/html; charset=utf-8",
                            "Location: " + location + "\r\n" + extra_headers);
}

std::string login_state_page_html(const std::string& current_user, const std::string& message) {
  std::ostringstream os;
  os << "<!doctype html><html><head><meta charset=\"utf-8\"><title>OpenScanProxy Login</title><style>"
     << "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#09121f;color:#e6edf8;"
     << "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;}"
     << ".card{width:min(460px,92vw);background:#132238;border:1px solid #27405f;border-radius:18px;padding:28px;"
     << "box-shadow:0 16px 40px rgba(0,0,0,.28);}"
     << "h1{margin:0 0 10px;font-size:28px;}p{color:#9fb2cd;line-height:1.6;}"
     << ".meta{margin-top:14px;color:#c7d4e7;font-size:14px;word-break:break-all;}"
     << "</style></head><body><div class=\"card\"><h1>OpenScanProxy 认证</h1>"
     << "<p>" << html_escape(message) << "</p>";
  if (!current_user.empty()) {
    os << "<div class=\"meta\">当前登录用户: " << html_escape(current_user) << "</div>";
  }
  os << "</div></body></html>";
  return os.str();
}

std::string login_page_html(const std::string& return_to, const std::string& error, const std::string& current_user = "") {
  std::ostringstream os;
  os << "<!doctype html><html><head><meta charset=\"utf-8\"><title>OpenScanProxy Login</title><style>"
     << "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#09121f;color:#e6edf8;"
     << "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;}"
     << ".card{width:min(460px,92vw);background:#132238;border:1px solid #27405f;border-radius:18px;padding:28px;"
     << "box-shadow:0 16px 40px rgba(0,0,0,.28);}"
     << "h1{margin:0 0 10px;font-size:28px;}p{color:#9fb2cd;line-height:1.6;}label{display:block;margin-top:14px;"
     << "font-size:13px;color:#c7d4e7;}input{width:100%;box-sizing:border-box;margin-top:8px;padding:12px 14px;"
     << "border-radius:12px;border:1px solid #2f4f75;background:#0c1828;color:#eef4ff;}"
     << "button{margin-top:18px;width:100%;padding:12px 16px;border-radius:12px;border:1px solid #476f9d;"
     << "background:#24456e;color:#fff;font-weight:600;cursor:pointer;}"
     << ".error{margin-top:12px;padding:10px 12px;border-radius:10px;background:#3b1418;color:#ffced3;}"
     << ".meta{margin-top:14px;color:#8ea3bf;font-size:12px;word-break:break-all;}"
     << "</style></head><body><div class=\"card\"><h1>OpenScanProxy 认证</h1>"
     << "<p>登录成功后，浏览器会为当前访问站点建立代理认证 cookie，后续访问同域名时无需重复输入用户名和密码。</p>";
  if (!error.empty()) {
    os << "<div class=\"error\">" << html_escape(error) << "</div>";
  }
  if (!current_user.empty()) {
    os << "<div class=\"meta\">当前登录用户: " << html_escape(current_user) << "</div>";
  }
  os << "<form method=\"post\" action=\"/login\">"
     << "<input type=\"hidden\" name=\"return_to\" value=\"" << html_escape(return_to) << "\">"
     << "<label>用户名<input name=\"username\" autocomplete=\"username\"></label>"
     << "<label>密码<input name=\"password\" type=\"password\" autocomplete=\"current-password\"></label>"
     << "<button type=\"submit\">登录并继续访问</button></form>";
  if (!return_to.empty()) {
    os << "<div class=\"meta\">返回地址: " << html_escape(return_to) << "</div>";
  } else {
    os << "<div class=\"meta\">登录成功后，将在后续访问目标站点时自动完成域认证。</div>";
  }
  os << "</div></body></html>";
  return os.str();
}

audit::AuditEvent make_auth_event(const std::string& client_addr, const std::string& action, const std::string& user,
                                  const std::string& decision_source, const std::string& url) {
  audit::AuditEvent event;
  event.event_type = "auth";
  event.timestamp = core::now_iso8601();
  event.client_addr = client_addr;
  event.user = user.empty() ? "-" : user;
  event.url = url;
  event.action = action;
  event.decision_source = decision_source;
  return event;
}

}  // namespace

void AuthPortalServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    core::app_logger().log(core::LogLevel::Error, "auth portal: socket() failed");
    return;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.proxy_auth_portal_listen_port);
  inet_pton(AF_INET, runtime_.config.proxy_auth_portal_listen_host.c_str(), &addr.sin_addr);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    core::app_logger().log(core::LogLevel::Error,
                           "auth portal: bind() failed on " + runtime_.config.proxy_auth_portal_listen_host + ":" +
                               std::to_string(runtime_.config.proxy_auth_portal_listen_port));
    close(fd);
    return;
  }
  if (listen(fd, 64) != 0) {
    core::app_logger().log(core::LogLevel::Error, "auth portal: listen() failed");
    close(fd);
    return;
  }

  std::unique_ptr<SSL_CTX, void (*)(SSL_CTX*)> server_ctx(
      runtime_.tls_mitm.create_server_ctx_for_host(runtime_.config.proxy_auth_portal_listen_host), SSL_CTX_free);
  if (!server_ctx) {
    core::app_logger().log(core::LogLevel::Error, "auth portal: failed to create TLS server context");
    close(fd);
    return;
  }

  core::app_logger().log(core::LogLevel::Info,
                         "auth portal listening on https://" + runtime_.config.proxy_auth_portal_listen_host + ":" +
                             std::to_string(runtime_.config.proxy_auth_portal_listen_port));

  while (true) {
    sockaddr_in caddr{};
    socklen_t len = sizeof(caddr);
    int cfd = accept(fd, reinterpret_cast<sockaddr*>(&caddr), &len);
    if (cfd < 0) continue;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
    std::string client_addr = std::string(ip) + ":" + std::to_string(ntohs(caddr.sin_port));

    std::thread([this, cfd, client_addr, server_ctx_raw = server_ctx.get()]() {
      std::unique_ptr<SSL, void (*)(SSL*)> ssl(SSL_new(server_ctx_raw), SSL_free);
      if (!ssl) {
        close(cfd);
        return;
      }
      SSL_set_fd(ssl.get(), cfd);
      if (SSL_accept(ssl.get()) != 1) {
        SSL_shutdown(ssl.get());
        close(cfd);
        return;
      }

      std::string req;
      if (!read_http_message_over_ssl(ssl.get(), req)) {
        SSL_shutdown(ssl.get());
        close(cfd);
        return;
      }

      auto line_end = req.find("\r\n");
      if (line_end == std::string::npos) {
        SSL_shutdown(ssl.get());
        close(cfd);
        return;
      }
      std::istringstream fl(req.substr(0, line_end));
      std::string method;
      std::string path;
      fl >> method >> path;

      auto cookies = parse_cookie_header(get_header(req, "Cookie"));
      auto portal_cookie_it = cookies.find(runtime_.config.proxy_auth_portal_cookie_name);
      auto current_user = portal_cookie_it == cookies.end() ? "" : runtime_.portal_sessions.lookup_user(portal_cookie_it->second);
      auto query = parse_query(path);
      auto return_to = query.count("return_to") ? query.at("return_to") : "";

      std::string resp;
      if (path.rfind("/login", 0) == 0 && method == "GET") {
        if (!return_to.empty() && !valid_return_to(runtime_, return_to)) {
          resp = make_http_response(400, "Bad Request", "<html><body>invalid return_to</body></html>");
        } else if (!current_user.empty() && !return_to.empty()) {
          auto target_host = extract_host_from_url(return_to);
          auto token = runtime_.domain_tokens.issue(current_user, target_host, runtime_.config.proxy_auth_token_ttl_sec);
          runtime_.audit.write(make_auth_event(client_addr, "allow", current_user, "proxy_auth_portal_auto", return_to));
          resp = redirect_response(append_auth_token(return_to, token));
        } else if (!current_user.empty()) {
          resp = make_http_response(200, "OK",
                                    login_state_page_html(current_user, "Portal 已登录。访问目标站点时会自动建立域认证。"));
        } else {
          resp = make_http_response(200, "OK", login_page_html(return_to, "", current_user));
        }
      } else if (path == "/login" && method == "POST") {
        auto form = parse_form(get_body(req));
        auto username = core::trim(form["username"]);
        auto password = form["password"];
        auto posted_return_to = form["return_to"];
        if (!posted_return_to.empty() && !valid_return_to(runtime_, posted_return_to)) {
          resp = make_http_response(400, "Bad Request", login_page_html(posted_return_to, "回跳地址不合法"));
        } else if (!runtime_.proxy_auth.authenticate(username, password)) {
          runtime_.audit.write(make_auth_event(client_addr, "block", username, "proxy_auth_portal_login_failed", posted_return_to));
          resp = make_http_response(401, "Unauthorized", login_page_html(posted_return_to, "用户名或密码错误"));
        } else {
          auto session_id = runtime_.portal_sessions.create(username, runtime_.config.proxy_auth_portal_session_ttl_sec);
          runtime_.portal_client_auth.upsert(client_ip_from_addr(client_addr), username,
                                             runtime_.config.proxy_auth_portal_session_ttl_sec);
          auto cookie_header = "Set-Cookie: " + runtime_.config.proxy_auth_portal_cookie_name + "=" + session_id +
                               "; HttpOnly; Secure; Path=/; Max-Age=" +
                               std::to_string(runtime_.config.proxy_auth_portal_session_ttl_sec) + "\r\n";
          runtime_.audit.write(make_auth_event(client_addr, "allow", username, "proxy_auth_portal_login", posted_return_to));
          if (!posted_return_to.empty()) {
            auto target_host = extract_host_from_url(posted_return_to);
            auto token = runtime_.domain_tokens.issue(username, target_host, runtime_.config.proxy_auth_token_ttl_sec);
            resp = redirect_response(append_auth_token(posted_return_to, token), cookie_header);
          } else {
            resp = make_http_response(200, "OK",
                                      login_state_page_html(username, "登录成功。后续访问目标站点时会自动完成代理认证。"),
                                      "text/html; charset=utf-8", cookie_header);
          }
        }
      } else if (path == "/logout" && method == "POST") {
        if (portal_cookie_it != cookies.end()) runtime_.portal_sessions.destroy(portal_cookie_it->second);
        runtime_.portal_client_auth.destroy(client_ip_from_addr(client_addr));
        runtime_.audit.write(make_auth_event(client_addr, "logout", current_user, "proxy_auth_portal_logout", path));
        resp = make_http_response(200, "OK", "{\"ok\":true}", "application/json; charset=utf-8",
                                  "Set-Cookie: " + runtime_.config.proxy_auth_portal_cookie_name +
                                      "=; Max-Age=0; HttpOnly; Secure; Path=/\r\n");
      } else if (path.rfind("/session", 0) == 0 && method == "GET") {
        std::ostringstream os;
        os << "{\"authenticated\":" << (!current_user.empty() ? "true" : "false")
           << ",\"username\":\"" << core::json_escape(current_user) << "\"}";
        resp = make_http_response(200, "OK", os.str(), "application/json; charset=utf-8");
      } else {
        resp = make_http_response(404, "Not Found", "<html><body>not found</body></html>");
      }

      ssl_write_all(ssl.get(), resp.data(), resp.size());
      SSL_shutdown(ssl.get());
      close(cfd);
    }).detach();
  }
}

}  // namespace openscanproxy::auth
