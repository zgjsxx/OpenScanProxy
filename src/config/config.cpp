#include "openscanproxy/config/config.hpp"

#include "openscanproxy/core/util.hpp"

#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace openscanproxy::config {
namespace {

std::string read_all(const std::string& path) {
  std::ifstream ifs(path);
  if (!ifs) throw std::runtime_error("failed to open config: " + path);
  std::stringstream ss;
  ss << ifs.rdbuf();
  return ss.str();
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

std::vector<policy::AccessRule> parse_access_rules(const std::string& text) {
  std::vector<policy::AccessRule> rules;
  std::regex arr("\\\"access_rules\\\"\\s*:\\s*\\[(.*)\\]", std::regex::icase);
  std::smatch arr_match;
  if (!std::regex_search(text, arr_match, arr)) return rules;
  const auto body = arr_match[1].str();

  std::regex obj("\\{([^\\{\\}]*)\\}");
  for (std::sregex_iterator it(body.begin(), body.end(), obj), end; it != end; ++it) {
    const auto item = (*it)[0].str();
    auto kv = core::parse_simple_json_object(item);
    policy::AccessRule rule;
    if (kv.count("name")) rule.name = kv.at("name");
    rule.users = parse_string_array(item, "users");
    rule.domain_whitelist = parse_string_array(item, "domain_whitelist");
    rule.domain_blacklist = parse_string_array(item, "domain_blacklist");
    rule.url_whitelist = parse_string_array(item, "url_whitelist");
    rule.url_blacklist = parse_string_array(item, "url_blacklist");
    rule.url_category_whitelist = parse_string_array(item, "url_category_whitelist");
    rule.url_category_blacklist = parse_string_array(item, "url_category_blacklist");
    rules.push_back(std::move(rule));
  }
  return rules;
}

bool as_bool(const std::string& v) { return v == "true" || v == "1"; }

}  // namespace

AppConfig ConfigLoader::load_from_file(const std::string& path) {
  auto text = read_all(path);
  auto kv = core::parse_simple_json_object(text);

  AppConfig cfg;
#define GET_S(key, field) if (kv.count(key)) cfg.field = kv.at(key)
#define GET_U16(key, field) if (kv.count(key)) cfg.field = static_cast<uint16_t>(std::stoi(kv.at(key)))
#define GET_US(key, field) if (kv.count(key)) cfg.field = static_cast<std::size_t>(std::stoull(kv.at(key)))
#define GET_U64(key, field) if (kv.count(key)) cfg.field = static_cast<uint64_t>(std::stoull(kv.at(key)))
#define GET_B(key, field) if (kv.count(key)) cfg.field = as_bool(kv.at(key))

  GET_S("proxy_listen_host", proxy_listen_host);
  GET_U16("proxy_listen_port", proxy_listen_port);
  GET_S("admin_listen_host", admin_listen_host);
  GET_U16("admin_listen_port", admin_listen_port);
  GET_S("admin_static_dir", admin_static_dir);
  GET_S("ca_cert_path", ca_cert_path);
  GET_S("ca_key_path", ca_key_path);
  GET_B("enable_https_mitm", enable_https_mitm);
  GET_B("scan_upload", scan_upload);
  GET_B("scan_download", scan_download);
  GET_US("max_scan_file_size", max_scan_file_size);
  GET_U64("scan_timeout_ms", scan_timeout_ms);
  GET_S("policy_mode", policy_mode);
  GET_S("suspicious_action", suspicious_action);
  GET_S("default_access_action", default_access_action);
  GET_S("scanner_type", scanner_type);
  GET_S("clamav_mode", clamav_mode);
  GET_S("clamav_unix_socket", clamav_unix_socket);
  GET_S("clamav_host", clamav_host);
  GET_U16("clamav_port", clamav_port);
  GET_S("audit_log_path", audit_log_path);
  GET_US("audit_recent_limit", audit_recent_limit);
  GET_S("app_log_path", app_log_path);
  GET_S("app_log_level", app_log_level);
  GET_US("app_log_max_files", app_log_max_files);
  GET_US("app_log_max_size_mb", app_log_max_size_mb);
  GET_S("admin_user", admin_user);
  GET_S("admin_password", admin_password);
  GET_B("enable_proxy_auth", enable_proxy_auth);
  GET_S("proxy_auth_mode", proxy_auth_mode);
  GET_S("proxy_auth_user", proxy_auth_user);
  GET_S("proxy_auth_password", proxy_auth_password);
  GET_S("proxy_users_file", proxy_users_file);
  GET_S("proxy_auth_portal_listen_host", proxy_auth_portal_listen_host);
  GET_U16("proxy_auth_portal_listen_port", proxy_auth_portal_listen_port);
  GET_S("proxy_auth_cookie_name", proxy_auth_cookie_name);
  GET_S("proxy_auth_portal_cookie_name", proxy_auth_portal_cookie_name);
  GET_U64("proxy_auth_token_ttl_sec", proxy_auth_token_ttl_sec);
  GET_U64("proxy_auth_portal_session_ttl_sec", proxy_auth_portal_session_ttl_sec);
  GET_S("proxy_auth_signing_key", proxy_auth_signing_key);
  GET_S("domain_category_data_file", domain_category_data_file);

  cfg.allowed_mime = parse_string_array(text, "allowed_mime");
  cfg.allowed_extensions = parse_string_array(text, "allowed_extensions");
  cfg.domain_whitelist = parse_string_array(text, "domain_whitelist");
  cfg.domain_blacklist = parse_string_array(text, "domain_blacklist");
  cfg.user_whitelist = parse_string_array(text, "user_whitelist");
  cfg.user_blacklist = parse_string_array(text, "user_blacklist");
  cfg.url_whitelist = parse_string_array(text, "url_whitelist");
  cfg.url_blacklist = parse_string_array(text, "url_blacklist");
  cfg.url_category_whitelist = parse_string_array(text, "url_category_whitelist");
  cfg.url_category_blacklist = parse_string_array(text, "url_category_blacklist");
  cfg.access_rules = parse_access_rules(text);
  if (cfg.proxy_auth_mode != "basic" && cfg.proxy_auth_mode != "portal" && cfg.proxy_auth_mode != "hybrid") {
    cfg.proxy_auth_mode = "basic";
  }
  if (cfg.default_access_action != "allow" && cfg.default_access_action != "block") {
    cfg.default_access_action = "allow";
  }
  if (cfg.proxy_auth_portal_session_ttl_sec == 0) cfg.proxy_auth_portal_session_ttl_sec = 3600;
  if (cfg.proxy_auth_token_ttl_sec == 0) cfg.proxy_auth_token_ttl_sec = 120;
  if (cfg.proxy_auth_cookie_name.empty()) cfg.proxy_auth_cookie_name = "osp_proxy_auth";
  if (cfg.proxy_auth_portal_cookie_name.empty()) cfg.proxy_auth_portal_cookie_name = "osp_portal_session";
  if (cfg.proxy_auth_signing_key.empty()) {
    cfg.proxy_auth_signing_key = cfg.admin_password + ":" + cfg.proxy_auth_password + ":openscanproxy";
  }
  return cfg;
}

}  // namespace openscanproxy::config
