#include "openscanproxy/config/config.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

using openscanproxy::config::AppConfig;
using openscanproxy::config::ConfigLoader;

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

std::string write_config_file(const std::string& name, const std::string& body) {
  const std::string path = "build/" + name;
  std::ofstream ofs(path, std::ios::trunc);
  ofs << body;
  return path;
}

bool test_defaults_and_invalid_values_fallback() {
  const std::string path = write_config_file(
      "config_defaults_test.json",
      R"({
        "proxy_auth_portal_session_ttl_sec": 0,
        "proxy_auth_token_ttl_sec": 0,
        "proxy_auth_cookie_name": "",
        "proxy_auth_portal_cookie_name": "",
        "proxy_auth_portal_session_file": "",
        "proxy_auth_client_cache_file": "",
        "proxy_auth_signing_key": "",
        "tls_leaf_cache_dir": ""
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.proxy_auth_cookie_name == "osp_proxy_auth", "empty proxy auth cookie falls back to default") &&
         expect(cfg.proxy_auth_portal_cookie_name == "osp_portal_session",
                "empty portal cookie falls back to default") &&
         expect(cfg.proxy_auth_portal_session_file == "./configs/portal_sessions.json",
                "empty portal session file falls back to default") &&
         expect(cfg.proxy_auth_client_cache_file == "./configs/portal_client_auth_cache.json",
                "empty client cache file falls back to default") &&
         expect(cfg.proxy_auth_token_ttl_sec == 120, "zero token ttl falls back to default") &&
         expect(cfg.proxy_auth_portal_session_ttl_sec == 3600, "zero portal ttl falls back to default") &&
         expect(cfg.tls_leaf_cache_dir == "./certs/cache", "empty tls leaf cache dir falls back to default") &&
         expect(cfg.proxy_auth_signing_key == "openscanproxy-default-signing-key-change-me",
                "empty signing key falls back to default");
}

bool test_scalar_values_are_loaded() {
  const std::string path = write_config_file(
      "config_scalars_test.json",
      R"({
        "proxy_listen_host": "127.0.0.1",
        "proxy_listen_port": 18080,
        "admin_listen_port": 9999,
        "tls_leaf_cache_enabled": true,
        "scanner_type": "clamav",
        "clamav_port": 9998,
        "audit_recent_limit": 1000,
        "app_log_level": "debug",
        "app_log_max_files": 7,
        "app_log_max_size_mb": 20,
        "proxy_auth_portal_listen_port": 9997,
        "proxy_auth_token_ttl_sec": 240,
        "proxy_auth_portal_session_ttl_sec": 7200
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.proxy_listen_host == "127.0.0.1", "proxy listen host loaded") &&
         expect(cfg.proxy_listen_port == 18080, "proxy listen port loaded") &&
         expect(cfg.admin_listen_port == 9999, "admin listen port loaded") &&
         expect(cfg.tls_leaf_cache_enabled, "bool true loaded") &&
         expect(cfg.scanner_type == "clamav", "scanner type loaded") &&
         expect(cfg.clamav_port == 9998, "clamav port loaded") &&
         expect(cfg.audit_recent_limit == 1000, "audit recent limit loaded") &&
         expect(cfg.app_log_level == "debug", "log level loaded") &&
         expect(cfg.app_log_max_files == 7, "log max files loaded") &&
         expect(cfg.app_log_max_size_mb == 20, "log max size loaded") &&
         expect(cfg.proxy_auth_portal_listen_port == 9997, "portal port loaded") &&
         expect(cfg.proxy_auth_token_ttl_sec == 240, "token ttl loaded") &&
         expect(cfg.proxy_auth_portal_session_ttl_sec == 7200, "portal ttl loaded");
}

bool test_db_env_override() {
  const std::string path = write_config_file(
      "config_db_test.json",
      R"({
        "db_host": "localhost",
        "db_port": 5432,
        "db_name": "testdb",
        "db_user": "testuser",
        "db_password": "testpass"
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.db_host == "localhost", "db host loaded") &&
         expect(cfg.db_port == 5432, "db port loaded") &&
         expect(cfg.db_name == "testdb", "db name loaded") &&
         expect(cfg.db_user == "testuser", "db user loaded") &&
         expect(cfg.db_password == "testpass", "db password loaded");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_defaults_and_invalid_values_fallback() && ok;
  ok = test_scalar_values_are_loaded() && ok;
  ok = test_db_env_override() && ok;
  if (ok) {
    std::cout << "All config tests passed\n";
    return 0;
  }
  return 1;
}
