#include "openscanproxy/config/config.hpp"

#include "openscanproxy/core/util.hpp"

#include <cstdlib>
#include <fstream>
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
  GET_B("tls_leaf_cache_enabled", tls_leaf_cache_enabled);
  GET_S("tls_leaf_cache_dir", tls_leaf_cache_dir);
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
  GET_S("proxy_auth_portal_listen_host", proxy_auth_portal_listen_host);
  GET_U16("proxy_auth_portal_listen_port", proxy_auth_portal_listen_port);
  GET_S("proxy_auth_cookie_name", proxy_auth_cookie_name);
  GET_S("proxy_auth_insecure_cookie_name", proxy_auth_insecure_cookie_name);
  GET_S("proxy_auth_portal_cookie_name", proxy_auth_portal_cookie_name);
  GET_S("proxy_auth_portal_session_file", proxy_auth_portal_session_file);
  GET_S("proxy_auth_client_cache_file", proxy_auth_client_cache_file);
  GET_U64("proxy_auth_token_ttl_sec", proxy_auth_token_ttl_sec);
  GET_U64("proxy_auth_portal_session_ttl_sec", proxy_auth_portal_session_ttl_sec);
  GET_S("proxy_auth_signing_key", proxy_auth_signing_key);
  GET_S("domain_category_data_file", domain_category_data_file);

  GET_S("db_host", db_host);
  GET_U16("db_port", db_port);
  GET_S("db_name", db_name);
  GET_S("db_user", db_user);
  GET_S("db_password", db_password);

  // 环境变量覆盖数据库连接参数
  if (const char* ev = std::getenv("OSPROXY_DB_HOST")) cfg.db_host = ev;
  if (const char* ev = std::getenv("OSPROXY_DB_PORT")) {
    try { cfg.db_port = static_cast<uint16_t>(std::stoi(ev)); } catch (...) {}
  }
  if (const char* ev = std::getenv("OSPROXY_DB_NAME")) cfg.db_name = ev;
  if (const char* ev = std::getenv("OSPROXY_DB_USER")) cfg.db_user = ev;
  if (const char* ev = std::getenv("OSPROXY_DB_PASSWORD")) cfg.db_password = ev;

  if (cfg.proxy_auth_portal_session_ttl_sec == 0) cfg.proxy_auth_portal_session_ttl_sec = 3600;
  if (cfg.proxy_auth_token_ttl_sec == 0) cfg.proxy_auth_token_ttl_sec = 120;
  if (cfg.proxy_auth_cookie_name.empty()) cfg.proxy_auth_cookie_name = "osp_proxy_auth";
  if (cfg.proxy_auth_insecure_cookie_name.empty()) cfg.proxy_auth_insecure_cookie_name = "osp_proxy_auth_insecure";
  if (cfg.proxy_auth_portal_cookie_name.empty()) cfg.proxy_auth_portal_cookie_name = "osp_portal_session";
  if (cfg.proxy_auth_portal_session_file.empty()) cfg.proxy_auth_portal_session_file = "./configs/portal_sessions.json";
  if (cfg.proxy_auth_client_cache_file.empty()) cfg.proxy_auth_client_cache_file = "./configs/portal_client_auth_cache.json";
  if (cfg.proxy_auth_signing_key.empty()) {
    cfg.proxy_auth_signing_key = "openscanproxy-default-signing-key-change-me";
  }
  if (cfg.tls_leaf_cache_dir.empty()) cfg.tls_leaf_cache_dir = "./certs/cache";
  return cfg;
}

}  // namespace openscanproxy::config
