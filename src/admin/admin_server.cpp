#include "openscanproxy/admin/admin_server.hpp"

#include "openscanproxy/core/logger.hpp"
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
#include <regex>
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

std::vector<std::string> parse_string_array(const std::string& text, const std::string& key) {
  std::regex arr("\\\"" + key + "\\\"\\s*:\\s*\\[(.*?)\\]", std::regex::icase);
  std::smatch m;
  if (!std::regex_search(text, m, arr)) return {};
  std::vector<std::string> out;
  std::regex item("\\\"([^\\\"]*)\\\"");
  for (std::sregex_iterator it(m[1].first, m[1].second, item), end; it != end; ++it) out.push_back((*it)[1].str());
  return out;
}

std::string json_array(const std::vector<std::string>& values, bool lower_case = false) {
  std::ostringstream os;
  os << "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i) os << ",";
    auto v = lower_case ? lower(values[i]) : values[i];
    os << "\"" << core::json_escape(v) << "\"";
  }
  os << "]";
  return os.str();
}

std::string access_rules_json_array(const std::vector<policy::AccessRule>& rules) {
  std::ostringstream os;
  os << "[";
  for (std::size_t i = 0; i < rules.size(); ++i) {
    if (i) os << ",";
    const auto& r = rules[i];
    os << "{";
    os << "\"name\":\"" << core::json_escape(r.name) << "\",";
    os << "\"users\":" << json_array(r.users, true) << ",";
    os << "\"domain_whitelist\":" << json_array(r.domain_whitelist, true) << ",";
    os << "\"domain_blacklist\":" << json_array(r.domain_blacklist, true) << ",";
    os << "\"url_whitelist\":" << json_array(r.url_whitelist) << ",";
    os << "\"url_blacklist\":" << json_array(r.url_blacklist) << ",";
    os << "\"url_category_whitelist\":" << json_array(r.url_category_whitelist, true) << ",";
    os << "\"url_category_blacklist\":" << json_array(r.url_category_blacklist, true);
    os << "}";
  }
  os << "]";
  return os.str();
}

std::vector<policy::AccessRule> parse_access_rules(const std::string& text) {
  std::vector<policy::AccessRule> rules;
  std::regex arr("\\\"access_rules\\\"\\s*:\\s*\\[(.*)\\]", std::regex::icase);
  std::smatch arr_match;
  if (!std::regex_search(text, arr_match, arr)) return rules;
  auto body = arr_match[1].str();
  std::regex obj("\\{([^\\{\\}]*)\\}");
  for (std::sregex_iterator it(body.begin(), body.end(), obj), end; it != end; ++it) {
    const auto item = (*it)[0].str();
    auto kv = core::parse_simple_json_object(item);
    policy::AccessRule r;
    if (kv.count("name")) r.name = kv.at("name");
    r.users = parse_string_array(item, "users");
    r.domain_whitelist = parse_string_array(item, "domain_whitelist");
    r.domain_blacklist = parse_string_array(item, "domain_blacklist");
    r.url_whitelist = parse_string_array(item, "url_whitelist");
    r.url_blacklist = parse_string_array(item, "url_blacklist");
    r.url_category_whitelist = parse_string_array(item, "url_category_whitelist");
    r.url_category_blacklist = parse_string_array(item, "url_category_blacklist");
    for (auto& u : r.users) u = lower(core::trim(u));
    for (auto& d : r.domain_whitelist) d = lower(core::trim(d));
    for (auto& d : r.domain_blacklist) d = lower(core::trim(d));
    for (auto& c : r.url_category_whitelist) c = lower(core::trim(c));
    for (auto& c : r.url_category_blacklist) c = lower(core::trim(c));
    rules.push_back(std::move(r));
  }
  return rules;
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

int parse_int_or(const std::map<std::string, std::string>& q, const std::string& key, int fallback) {
  auto it = q.find(key);
  if (it == q.end()) return fallback;
  try {
    return std::stoi(it->second);
  } catch (...) {
    return fallback;
  }
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
  os << "\"suspicious_action\":\"" << (p.block_suspicious ? "block" : "log") << "\",";
  os << "\"proxy_auth_enabled\":" << (runtime.proxy_auth.enabled() ? "true" : "false") << ",";
  os << "\"proxy_auth_mode\":\"" << core::json_escape(c.proxy_auth_mode) << "\",";
  os << "\"proxy_users_file\":\"" << core::json_escape(c.proxy_users_file) << "\"";
  os << "}";
  return os.str();
}

std::string auth_config_to_json(const proxy::Runtime& runtime) {
  const auto& c = runtime.config;
  std::ostringstream os;
  os << "{";
  os << "\"enable_proxy_auth\":" << (runtime.proxy_auth.enabled() ? "true" : "false") << ",";
  os << "\"proxy_auth_mode\":\"" << core::json_escape(c.proxy_auth_mode) << "\",";
  os << "\"enable_https_mitm\":" << (c.enable_https_mitm ? "true" : "false");
  os << "}";
  return os.str();
}

std::string proxy_users_to_json(const proxy::Runtime& runtime) {
  auto users = runtime.proxy_auth.list_users();
  std::sort(users.begin(), users.end());
  std::ostringstream os;
  os << "{";
  os << "\"enabled\":" << (runtime.proxy_auth.enabled() ? "true" : "false") << ",";
  os << "\"users\":[";
  for (std::size_t i = 0; i < users.size(); ++i) {
    if (i) os << ",";
    os << "{\"username\":\"" << core::json_escape(users[i]) << "\"}";
  }
  os << "]}";
  return os.str();
}

std::string access_policy_to_json(const proxy::Runtime& runtime) {
  auto p = runtime.policy.config();
  std::ostringstream os;
  os << "{";
  os << "\"domain_whitelist\":" << json_array(p.domain_whitelist, true) << ",";
  os << "\"domain_blacklist\":" << json_array(p.domain_blacklist, true) << ",";
  os << "\"user_whitelist\":" << json_array(p.user_whitelist, true) << ",";
  os << "\"user_blacklist\":" << json_array(p.user_blacklist, true) << ",";
  os << "\"url_whitelist\":" << json_array(p.url_whitelist) << ",";
  os << "\"url_blacklist\":" << json_array(p.url_blacklist) << ",";
  os << "\"url_category_whitelist\":" << json_array(p.url_category_whitelist, true) << ",";
  os << "\"url_category_blacklist\":" << json_array(p.url_category_blacklist, true) << ",";
  os << "\"access_rules\":" << access_rules_json_array(p.access_rules) << ",";
  os << "\"default_access_action\":\"" << policy::to_string(p.default_access_action) << "\"";
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
    os << "\"event_type\":\"" << core::json_escape(e.event_type) << "\",";
    os << "\"timestamp\":\"" << core::json_escape(e.timestamp) << "\",";
    os << "\"client_addr\":\"" << core::json_escape(e.client_addr) << "\",";
    os << "\"user\":\"" << core::json_escape(e.user) << "\",";
    os << "\"host\":\"" << core::json_escape(e.host) << "\",";
    os << "\"url\":\"" << core::json_escape(e.url) << "\",";
    os << "\"url_category\":\"" << core::json_escape(e.url_category) << "\",";
    os << "\"method\":\"" << core::json_escape(e.method) << "\",";
    os << "\"status_code\":" << e.status_code << ",";
    os << "\"latency_ms\":" << e.latency_ms << ",";
    os << "\"bytes_in\":" << e.bytes_in << ",";
    os << "\"bytes_out\":" << e.bytes_out << ",";
    os << "\"rule_hit\":\"" << core::json_escape(e.rule_hit) << "\",";
    os << "\"decision_source\":\"" << core::json_escape(e.decision_source) << "\",";
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
  int offset = 0;
  limit = std::max(1, std::min(1000, parse_int_or(q, "limit", limit)));
  offset = std::max(0, parse_int_or(q, "offset", offset));
  const auto word = lower(q.count("q") ? q.at("q") : "");
  const auto act = lower(q.count("action") ? q.at("action") : "");
  const auto res = lower(q.count("result") ? q.at("result") : "");
  const auto host = lower(q.count("host") ? q.at("host") : "");
  const auto method = lower(q.count("method") ? q.at("method") : "");
  const auto user = lower(q.count("user") ? q.at("user") : "");
  const auto path = lower(q.count("path") ? q.at("path") : "");
  const auto event_type = lower(q.count("event_type") ? q.at("event_type") : "");
  const int status = parse_int_or(q, "status", -1);
  const auto time_from = q.count("time_from") ? q.at("time_from") : "";
  const auto time_to = q.count("time_to") ? q.at("time_to") : "";

  std::vector<audit::AuditEvent> out;
  int skipped = 0;
  for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
    const auto& e = *it;
    const auto ehost = lower(e.host);
    const auto text = lower(e.url + " " + e.host + " " + e.filename + " " + e.signature);
    if (!act.empty() && lower(e.action) != act) continue;
    if (!res.empty() && lower(e.result) != res) continue;
    if (!method.empty() && lower(e.method) != method) continue;
    if (!user.empty() && lower(e.user).find(user) == std::string::npos) continue;
    if (status >= 0 && e.status_code != status) continue;
    if (!path.empty() && lower(e.url).find(path) == std::string::npos) continue;
    if (!host.empty() && ehost.find(host) == std::string::npos) continue;
    if (!event_type.empty() && lower(e.event_type) != event_type) continue;
    if (!time_from.empty() && e.timestamp < time_from) continue;
    if (!time_to.empty() && e.timestamp > time_to) continue;
    if (!word.empty() && text.find(word) == std::string::npos) continue;
    if (skipped < offset) {
      ++skipped;
      continue;
    }
    out.push_back(e);
    if (static_cast<int>(out.size()) >= limit) break;
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
  if (fd < 0) {
    core::app_logger().log(core::LogLevel::Error, "admin: socket() failed");
    return;
  }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(runtime_.config.admin_listen_port);
  inet_pton(AF_INET, runtime_.config.admin_listen_host.c_str(), &addr.sin_addr);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    core::app_logger().log(core::LogLevel::Error,
                           "admin: bind() failed on " + runtime_.config.admin_listen_host + ":" +
                               std::to_string(runtime_.config.admin_listen_port));
    close(fd);
    return;
  }
  if (listen(fd, 64) != 0) {
    core::app_logger().log(core::LogLevel::Error, "admin: listen() failed");
    close(fd);
    return;
  }
  core::app_logger().log(core::LogLevel::Info,
                         "admin listening on " + runtime_.config.admin_listen_host + ":" +
                             std::to_string(runtime_.config.admin_listen_port));

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
      } else if (pure_path == "/api/ca-cert" && method == "GET") {
        auto ca_data = read_file(runtime_.config.ca_cert_path);
        if (ca_data.empty()) {
          resp = http_resp(404, "Not Found", "{\"error\":\"CA certificate not found\"}", "application/json");
        } else {
          resp = http_resp(200, "OK", std::move(ca_data), "application/x-x509-ca-cert",
                           "Content-Disposition: attachment; filename=\"OpenScanProxy-CA.crt\"\r\n");
        }
      } else if (pure_path == "/api/auth-config" && method == "GET") {
        resp = http_resp(200, "OK", auth_config_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/auth-config" && method == "POST") {
        auto kv = core::parse_simple_json_object(get_body(req));
        if (kv.count("enable_proxy_auth")) {
          bool en = kv["enable_proxy_auth"] == "true";
          runtime_.config.enable_proxy_auth = en;
          runtime_.proxy_auth.set_enabled(en);
        }
        if (kv.count("proxy_auth_mode")) {
          const auto& mode = kv["proxy_auth_mode"];
          if (mode == "basic" || mode == "portal" || mode == "hybrid") {
            runtime_.config.proxy_auth_mode = mode;
          }
        }
        if (kv.count("enable_https_mitm")) {
          runtime_.config.enable_https_mitm = kv["enable_https_mitm"] == "true";
        }
        if (runtime_.policy_store) {
          runtime_.policy_store->save_auth_config(
              runtime_.config.enable_proxy_auth, runtime_.config.proxy_auth_mode,
              runtime_.config.enable_https_mitm);
        }
        resp = http_resp(200, "OK", auth_config_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/proxy-users" && method == "GET") {
        resp = http_resp(200, "OK", proxy_users_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/proxy-users" && method == "POST") {
        auto kv = core::parse_simple_json_object(get_body(req));
        auto username = kv.count("username") ? core::trim(kv.at("username")) : "";
        auto password = kv.count("password") ? kv.at("password") : "";
        if (!runtime_.proxy_auth.upsert_user(username, password)) {
          resp = http_resp(400, "Bad Request", "{\"ok\":false,\"error\":\"username/password required\"}", "application/json");
        } else {
          runtime_.proxy_auth.set_enabled(true);
          runtime_.config.enable_proxy_auth = true;
          resp = http_resp(200, "OK", "{\"ok\":true}", "application/json");
        }
      } else if (pure_path == "/api/proxy-users" && method == "DELETE") {
        auto kv = core::parse_simple_json_object(get_body(req));
        auto username = kv.count("username") ? core::trim(kv.at("username")) : "";
        if (!runtime_.proxy_auth.remove_user(username)) {
          resp = http_resp(400, "Bad Request", "{\"ok\":false,\"error\":\"user not found\"}", "application/json");
        } else {
          resp = http_resp(200, "OK", "{\"ok\":true}", "application/json");
        }
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
        // Persist to database
        if (runtime_.policy_store) {
          policy::PolicyStore::ScanPolicy sp;
          sp.fail_open = p.fail_open;
          sp.block_suspicious = p.block_suspicious;
          sp.scan_upload = runtime_.config.scan_upload;
          sp.scan_download = runtime_.config.scan_download;
          sp.max_scan_file_size = runtime_.config.max_scan_file_size;
          sp.scan_timeout_ms = runtime_.config.scan_timeout_ms;
          sp.allowed_mime = runtime_.config.allowed_mime;
          sp.allowed_extensions = runtime_.config.allowed_extensions;
          runtime_.policy_store->save_scan_policy(sp);
        }
        resp = http_resp(200, "OK", "{\"ok\":true}", "application/json");
      } else if (pure_path == "/api/access-policy" && method == "GET") {
        resp = http_resp(200, "OK", access_policy_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/access-policy" && method == "POST") {
        auto body = get_body(req);
        auto kv = core::parse_simple_json_object(body);
        auto p = runtime_.policy.config();
        p.domain_whitelist = parse_string_array(body, "domain_whitelist");
        p.domain_blacklist = parse_string_array(body, "domain_blacklist");
        p.user_whitelist = parse_string_array(body, "user_whitelist");
        p.user_blacklist = parse_string_array(body, "user_blacklist");
        p.url_whitelist = parse_string_array(body, "url_whitelist");
        p.url_blacklist = parse_string_array(body, "url_blacklist");
        p.url_category_whitelist = parse_string_array(body, "url_category_whitelist");
        p.url_category_blacklist = parse_string_array(body, "url_category_blacklist");
        p.access_rules = parse_access_rules(body);
        for (auto& d : p.domain_whitelist) d = lower(core::trim(d));
        for (auto& d : p.domain_blacklist) d = lower(core::trim(d));
        for (auto& u : p.user_whitelist) u = lower(core::trim(u));
        for (auto& u : p.user_blacklist) u = lower(core::trim(u));
        for (auto& c : p.url_category_whitelist) c = lower(core::trim(c));
        for (auto& c : p.url_category_blacklist) c = lower(core::trim(c));
        if (kv.count("default_access_action")) {
          p.default_access_action = policy::access_action_from_string(kv["default_access_action"]);
        }
        runtime_.policy.update(p);
        runtime_.config.domain_whitelist = p.domain_whitelist;
        runtime_.config.domain_blacklist = p.domain_blacklist;
        runtime_.config.user_whitelist = p.user_whitelist;
        runtime_.config.user_blacklist = p.user_blacklist;
        runtime_.config.url_whitelist = p.url_whitelist;
        runtime_.config.url_blacklist = p.url_blacklist;
        runtime_.config.url_category_whitelist = p.url_category_whitelist;
        runtime_.config.url_category_blacklist = p.url_category_blacklist;
        runtime_.config.access_rules = p.access_rules;
        runtime_.config.default_access_action = policy::to_string(p.default_access_action);
        // Persist to database
        if (runtime_.policy_store) {
          runtime_.policy_store->save_policy(p);
        }
        resp = http_resp(200, "OK", access_policy_to_json(runtime_), "application/json");
      } else if (pure_path == "/api/policy/test" && method == "POST") {
        auto body = get_body(req);
        auto kv = core::parse_simple_json_object(body);
        auto host = kv.count("host") ? kv.at("host") : "";
        auto url = kv.count("url") ? kv.at("url") : "";
        auto req_method = kv.count("method") ? kv.at("method") : "GET";
        auto user = kv.count("user") ? kv.at("user") : "";
        auto r = runtime_.policy.evaluate_access(host, url, req_method, user);
        std::ostringstream out;
        out << "{";
        out << "\"user\":\"" << core::json_escape(user) << "\",";
        out << "\"host\":\"" << core::json_escape(host) << "\",";
        out << "\"url\":\"" << core::json_escape(url) << "\",";
        out << "\"method\":\"" << core::json_escape(req_method) << "\",";
        out << "\"url_category\":\"" << core::json_escape(r.url_category) << "\",";
        out << "\"matched_rule\":\"" << core::json_escape(r.matched_rule) << "\",";
        out << "\"matched_type\":\"" << core::json_escape(r.matched_type) << "\",";
        out << "\"reason\":\"" << core::json_escape(r.reason) << "\",";
        out << "\"action\":\"" << policy::to_string(r.action) << "\"";
        out << "}";
        resp = http_resp(200, "OK", out.str(), "application/json");
      } else {
        resp = serve_static(runtime_.config.admin_static_dir, pure_path == "/login" ? "/index.html" : pure_path);
      }
      send(c, resp.data(), resp.size(), 0);
      close(c);
    }).detach();
  }
}

}  // namespace openscanproxy::admin
