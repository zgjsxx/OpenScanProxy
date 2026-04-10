#include "openscanproxy/admin/admin_server.hpp"

#include "openscanproxy/core/util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>

namespace openscanproxy::admin {
namespace {
std::string http_resp(int status, const std::string& reason, const std::string& body,
                      const std::string& ct = "text/plain; charset=utf-8", const std::string& extra_headers = "") {
  std::ostringstream os;
  os << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
     << "Content-Type: " << ct << "\r\n"
     << "Cache-Control: no-store\r\n"
     << "Content-Length: " << body.size() << "\r\n"
     << extra_headers << "Connection: close\r\n\r\n"
     << body;
  return os.str();
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
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
  if (line_begin >= req.size()) return "";
  while (line_begin < req.size() && req[line_begin] == ' ') ++line_begin;
  auto line_end = req.find("\r\n", line_begin);
  if (line_end == std::string::npos) return "";
  return req.substr(line_begin, line_end - line_begin);
}

bool logged_in(const std::string& req) {
  auto cookie = get_header(req, "Cookie");
  return cookie.find("session=ok") != std::string::npos;
}

std::map<std::string, std::string> parse_form(const std::string& body) {
  std::map<std::string, std::string> out;
  auto pairs = core::split(body, '&');
  for (const auto& p : pairs) {
    auto eq = p.find('=');
    if (eq == std::string::npos) continue;
    out[p.substr(0, eq)] = p.substr(eq + 1);
  }
  return out;
}

std::map<std::string, std::string> parse_query(const std::string& path) {
  std::map<std::string, std::string> out;
  auto q = path.find('?');
  if (q == std::string::npos) return out;
  for (const auto& seg : core::split(path.substr(q + 1), '&')) {
    auto eq = seg.find('=');
    if (eq == std::string::npos) continue;
    out[seg.substr(0, eq)] = seg.substr(eq + 1);
  }
  return out;
}

std::string stats_to_json(const stats::Snapshot& s) {
  std::ostringstream os;
  os << "{";
  os << "\"total_requests\":" << s.total_requests << ",";
  os << "\"https_mitm_requests\":" << s.https_mitm_requests << ",";
  os << "\"scanned_files\":" << s.scanned_files << ",";
  os << "\"clean\":" << s.clean << ",";
  os << "\"infected\":" << s.infected << ",";
  os << "\"suspicious\":" << s.suspicious << ",";
  os << "\"blocked\":" << s.blocked << ",";
  os << "\"scanner_error\":" << s.scanner_error;
  os << "}";
  return os.str();
}

std::string config_to_json(const proxy::Runtime& runtime) {
  auto p = runtime.policy.config();
  const auto& c = runtime.config;
  std::ostringstream os;
  os << "{";
  os << "\"proxy\":\"" << core::json_escape(c.proxy_listen_host + ":" + std::to_string(c.proxy_listen_port)) << "\",";
  os << "\"admin\":\"" << core::json_escape(c.admin_listen_host + ":" + std::to_string(c.admin_listen_port)) << "\",";
  os << "\"admin_static_dir\":\"" << core::json_escape(c.admin_static_dir) << "\",";
  os << "\"https_mitm\":" << (c.enable_https_mitm ? "true" : "false") << ",";
  os << "\"scanner\":\"" << core::json_escape(c.scanner_type) << "\",";
  os << "\"policy_mode\":\"" << (p.fail_open ? "fail-open" : "fail-close") << "\",";
  os << "\"suspicious_action\":\"" << (p.block_suspicious ? "block" : "log") << "\"";
  os << "}";
  return os.str();
}

std::string logs_to_json(const std::vector<audit::AuditEvent>& logs) {
  std::ostringstream os;
  os << "[";
  for (size_t i = 0; i < logs.size(); ++i) {
    const auto& e = logs[i];
    if (i) os << ',';
    os << "{";
    os << "\"timestamp\":\"" << core::json_escape(e.timestamp) << "\",";
    os << "\"client_addr\":\"" << core::json_escape(e.client_addr) << "\",";
    os << "\"host\":\"" << core::json_escape(e.host) << "\",";
    os << "\"url\":\"" << core::json_escape(e.url) << "\",";
    os << "\"method\":\"" << core::json_escape(e.method) << "\",";
    os << "\"filename\":\"" << core::json_escape(e.filename) << "\",";
    os << "\"result\":\"" << core::json_escape(e.result) << "\",";
    os << "\"action\":\"" << core::json_escape(e.action) << "\",";
    os << "\"signature\":\"" << core::json_escape(e.signature) << "\"";
    os << "}";
  }
  os << "]";
  return os.str();
}

std::vector<audit::AuditEvent> filter_logs(std::vector<audit::AuditEvent> logs, const std::map<std::string, std::string>& q) {
  int limit = 100;
  if (auto it = q.find("limit"); it != q.end()) {
    limit = std::max(1, std::min(1000, std::stoi(it->second)));
  }
  const auto word = lower(q.count("q") ? q.at("q") : "");
  const auto act = lower(q.count("action") ? q.at("action") : "");
  const auto res = lower(q.count("result") ? q.at("result") : "");
  const auto host = lower(q.count("host") ? q.at("host") : "");

  std::vector<audit::AuditEvent> out;
  for (auto it = logs.rbegin(); it != logs.rend() && static_cast<int>(out.size()) < limit; ++it) {
    const auto& e = *it;
    const auto ehost = lower(e.host);
    const auto text = lower(e.url + " " + e.host + " " + e.filename + " " + e.signature);
    if (!act.empty() && lower(e.action) != act) continue;
    if (!res.empty() && lower(e.result) != res) continue;
    if (!host.empty() && ehost.find(host) == std::string::npos) continue;
    if (!word.empty() && text.find(word) == std::string::npos) continue;
    out.push_back(e);
  }
  std::reverse(out.begin(), out.end());
  return out;
}

std::string content_type_for(const std::filesystem::path& p) {
  auto ext = lower(p.extension().string());
  if (ext == ".html") return "text/html; charset=utf-8";
  if (ext == ".js") return "application/javascript; charset=utf-8";
  if (ext == ".css") return "text/css; charset=utf-8";
  if (ext == ".json") return "application/json; charset=utf-8";
  if (ext == ".svg") return "image/svg+xml";
  if (ext == ".png") return "image/png";
  if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
  if (ext == ".ico") return "image/x-icon";
  return "application/octet-stream";
}

std::string read_file(const std::filesystem::path& file) {
  std::ifstream ifs(file, std::ios::binary);
  if (!ifs) return "";
  std::ostringstream os;
  os << ifs.rdbuf();
  return os.str();
}

std::string serve_static(const std::filesystem::path& root, const std::string& req_path) {
  namespace fs = std::filesystem;
  std::string safe_path = req_path;
  if (safe_path.empty() || safe_path == "/") safe_path = "/index.html";
  fs::path rel = safe_path[0] == '/' ? safe_path.substr(1) : safe_path;
  fs::path target = root / rel;
  fs::path normalized = target.lexically_normal();

  if (normalized.string().find("..") != std::string::npos) {
    return http_resp(400, "Bad Request", "invalid path");
  }

  if (fs::exists(normalized) && fs::is_regular_file(normalized)) {
    auto body = read_file(normalized);
    return http_resp(200, "OK", body, content_type_for(normalized));
  }

  auto index_file = root / "index.html";
  if (fs::exists(index_file)) {
    auto body = read_file(index_file);
    return http_resp(200, "OK", body, "text/html; charset=utf-8");
  }
  return http_resp(404, "Not Found", "static file not found");
}

}  // namespace

void AdminServer::run() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.admin_listen_port);
  inet_pton(AF_INET, runtime_.config.admin_listen_host.c_str(), &addr.sin_addr);
  bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  listen(fd, 64);

  while (true) {
    int c = accept(fd, nullptr, nullptr);
    if (c < 0) continue;
    std::thread([this, c]() {
      char buf[65536] = {0};
      auto n = recv(c, buf, sizeof(buf) - 1, 0);
      if (n <= 0) {
        close(c);
        return;
      }
      std::string req(buf, n);
      auto line_end = req.find("\r\n");
      auto first = req.substr(0, line_end);
      std::istringstream fl(first);
      std::string method, path;
      fl >> method >> path;
      auto pure_path = path.substr(0, path.find('?'));

      std::string resp;
      if (pure_path == "/healthz" || pure_path == "/readyz") {
        resp = http_resp(200, "OK", "ok", "text/plain");
      } else if (pure_path == "/metrics") {
        resp = http_resp(200, "OK", runtime_.stats.to_metrics_text(), "text/plain");
      } else if (pure_path == "/api/login" && method == "POST") {
        auto body = get_body(req);
        auto kv = core::parse_simple_json_object(body);
        const auto u = kv.count("u") ? kv.at("u") : "";
        const auto p = kv.count("p") ? kv.at("p") : "";
        if (u == runtime_.config.admin_user && p == runtime_.config.admin_password) {
          resp = http_resp(200, "OK", "{\"ok\":true}", "application/json",
                           "Set-Cookie: session=ok; HttpOnly; Path=/\r\n");
        } else {
          resp = http_resp(401, "Unauthorized", "{\"ok\":false}", "application/json");
        }
      } else if (pure_path == "/api/logout" && method == "POST") {
        resp = http_resp(200, "OK", "{\"ok\":true}", "application/json",
                         "Set-Cookie: session=; Max-Age=0; HttpOnly; Path=/\r\n");
      } else if (pure_path == "/login" && method == "POST") {
        auto form = parse_form(get_body(req));
        const auto u = form.count("u") ? form["u"] : "";
        const auto p = form.count("p") ? form["p"] : "";
        bool ok = u == runtime_.config.admin_user && p == runtime_.config.admin_password;
        resp = ok ? http_resp(200, "OK", "{\"ok\":true}", "application/json",
                              "Set-Cookie: session=ok; HttpOnly; Path=/\r\n")
                  : http_resp(401, "Unauthorized", "{\"ok\":false}", "application/json");
      } else if (pure_path.rfind("/api/", 0) == 0 && !logged_in(req)) {
        resp = http_resp(401, "Unauthorized", "{\"error\":\"unauthorized\"}", "application/json");
      } else if (pure_path == "/api/stats") {
        resp = http_resp(200, "OK", stats_to_json(runtime_.stats.snapshot()), "application/json");
      } else if (pure_path == "/api/config") {
        resp = http_resp(200, "OK", config_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/logs") {
        auto logs = filter_logs(runtime_.audit.latest(1000), parse_query(path));
        resp = http_resp(200, "OK", logs_to_json(logs), "application/json");
      } else if (pure_path == "/api/policy" && method == "GET") {
        auto p = runtime_.policy.config();
        std::ostringstream body;
        body << "{\"fail_open\":" << (p.fail_open ? "true" : "false") << ",\"block_suspicious\":"
             << (p.block_suspicious ? "true" : "false") << "}";
        resp = http_resp(200, "OK", body.str(), "application/json");
      } else if (pure_path == "/api/policy" && method == "POST") {
        auto kv = core::parse_simple_json_object(get_body(req));
        auto p = runtime_.policy.config();
        if (kv.count("fail_open")) p.fail_open = kv["fail_open"] == "true";
        if (kv.count("block_suspicious")) p.block_suspicious = kv["block_suspicious"] == "true";
        runtime_.policy.update(p);
        runtime_.config.policy_mode = p.fail_open ? "fail-open" : "fail-close";
        runtime_.config.suspicious_action = p.block_suspicious ? "block" : "log";
        resp = http_resp(200, "OK", "{\"ok\":true}", "application/json");
      } else {
        if (!logged_in(req) && pure_path != "/login") {
          resp = http_resp(302, "Found", "", "text/plain", "Location: /login\r\n");
        } else {
          resp = serve_static(runtime_.config.admin_static_dir, pure_path == "/login" ? "/index.html" : pure_path);
        }
      }
      send(c, resp.data(), resp.size(), 0);
      close(c);
    }).detach();
  }
}

}  // namespace openscanproxy::admin
