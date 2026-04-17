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
        "admin_password": "admin-secret",
        "proxy_auth_password": "proxy-secret",
        "proxy_auth_mode": "invalid-mode",
        "default_access_action": "deny",
        "proxy_auth_cookie_name": "",
        "proxy_auth_portal_cookie_name": "",
        "proxy_auth_portal_session_file": "",
        "proxy_auth_client_cache_file": "",
        "proxy_auth_signing_key": "",
        "proxy_auth_token_ttl_sec": 0,
        "proxy_auth_portal_session_ttl_sec": 0,
        "tls_leaf_cache_dir": ""
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.proxy_auth_mode == "basic", "invalid proxy auth mode falls back to basic") &&
         expect(cfg.default_access_action == "allow", "invalid default access action falls back to allow") &&
         expect(cfg.proxy_auth_cookie_name == "osp_proxy_auth", "empty proxy auth cookie falls back to default") &&
         expect(cfg.proxy_auth_portal_cookie_name == "osp_portal_session",
                "empty portal cookie falls back to default") &&
         expect(cfg.proxy_auth_portal_session_file == "./configs/portal_sessions.json",
                "empty portal session file falls back to default") &&
         expect(cfg.proxy_auth_client_cache_file == "./configs/portal_client_auth_cache.json",
                "empty client cache file falls back to default") &&
         expect(cfg.proxy_auth_token_ttl_sec == 120, "zero token ttl falls back to default") &&
         expect(cfg.proxy_auth_portal_session_ttl_sec == 3600, "zero portal ttl falls back to default") &&
         expect(cfg.tls_leaf_cache_dir == "./certs/cache", "empty tls leaf cache dir falls back to default") &&
         expect(cfg.proxy_auth_signing_key == "admin-secret:proxy-secret:openscanproxy",
                "empty signing key is derived from configured passwords");
}

bool test_arrays_and_scalar_values_are_loaded() {
  const std::string path = write_config_file(
      "config_arrays_test.json",
      R"({
        "proxy_listen_host": "127.0.0.1",
        "proxy_listen_port": 18080,
        "enable_https_mitm": true,
        "scan_download": false,
        "max_scan_file_size": 2048,
        "scan_timeout_ms": 9876,
        "allowed_mime": ["application/pdf", "image/png"],
        "allowed_extensions": [".pdf", ".png"],
        "domain_whitelist": ["trusted.example.com"],
        "domain_blacklist": ["blocked.example.com"],
        "url_whitelist": ["/safe"],
        "url_blacklist": ["/danger"],
        "url_category_whitelist": ["developer"],
        "url_category_blacklist": ["gambling"]
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.proxy_listen_host == "127.0.0.1", "proxy listen host loaded") &&
         expect(cfg.proxy_listen_port == 18080, "proxy listen port loaded") &&
         expect(cfg.enable_https_mitm, "bool true loaded") &&
         expect(!cfg.scan_download, "bool false loaded") &&
         expect(cfg.max_scan_file_size == 2048, "size_t loaded") &&
         expect(cfg.scan_timeout_ms == 9876, "u64 loaded") &&
         expect(cfg.allowed_mime.size() == 2 && cfg.allowed_mime[0] == "application/pdf" &&
                    cfg.allowed_mime[1] == "image/png",
                "allowed_mime array loaded") &&
         expect(cfg.allowed_extensions.size() == 2 && cfg.allowed_extensions[0] == ".pdf" &&
                    cfg.allowed_extensions[1] == ".png",
                "allowed_extensions array loaded") &&
         expect(cfg.domain_whitelist.size() == 1 && cfg.domain_whitelist[0] == "trusted.example.com",
                "domain whitelist loaded") &&
         expect(cfg.domain_blacklist.size() == 1 && cfg.domain_blacklist[0] == "blocked.example.com",
                "domain blacklist loaded") &&
         expect(cfg.url_whitelist.size() == 1 && cfg.url_whitelist[0] == "/safe", "url whitelist loaded") &&
         expect(cfg.url_blacklist.size() == 1 && cfg.url_blacklist[0] == "/danger", "url blacklist loaded") &&
         expect(cfg.url_category_whitelist.size() == 1 && cfg.url_category_whitelist[0] == "developer",
                "category whitelist loaded") &&
         expect(cfg.url_category_blacklist.size() == 1 && cfg.url_category_blacklist[0] == "gambling",
                "category blacklist loaded");
}

bool test_access_rules_are_loaded_with_nested_arrays() {
  const std::string path = write_config_file(
      "config_access_rules_test.json",
      R"({
        "access_rules": [
          {
            "name": "allow-user001-developer",
            "users": ["user001"],
            "domain_whitelist": ["github.com"],
            "url_whitelist": ["/docs"],
            "url_category_whitelist": ["developer"]
          },
          {
            "name": "block-user002-shopping",
            "users": ["user002"],
            "domain_blacklist": ["shop.example.com"],
            "url_blacklist": ["/checkout"],
            "url_category_blacklist": ["shopping"]
          }
        ]
      })");

  const AppConfig cfg = ConfigLoader::load_from_file(path);
  std::remove(path.c_str());

  return expect(cfg.access_rules.size() == 2, "two access rules loaded") &&
         expect(cfg.access_rules[0].name == "allow-user001-developer", "first rule name loaded") &&
         expect(cfg.access_rules[0].users.size() == 1 && cfg.access_rules[0].users[0] == "user001",
                "first rule users loaded") &&
         expect(cfg.access_rules[0].domain_whitelist.size() == 1 &&
                    cfg.access_rules[0].domain_whitelist[0] == "github.com",
                "first rule domain whitelist loaded") &&
         expect(cfg.access_rules[0].url_whitelist.size() == 1 && cfg.access_rules[0].url_whitelist[0] == "/docs",
                "first rule url whitelist loaded") &&
         expect(cfg.access_rules[0].url_category_whitelist.size() == 1 &&
                    cfg.access_rules[0].url_category_whitelist[0] == "developer",
                "first rule category whitelist loaded") &&
         expect(cfg.access_rules[1].name == "block-user002-shopping", "second rule name loaded") &&
         expect(cfg.access_rules[1].users.size() == 1 && cfg.access_rules[1].users[0] == "user002",
                "second rule users loaded") &&
         expect(cfg.access_rules[1].domain_blacklist.size() == 1 &&
                    cfg.access_rules[1].domain_blacklist[0] == "shop.example.com",
                "second rule domain blacklist loaded") &&
         expect(cfg.access_rules[1].url_blacklist.size() == 1 && cfg.access_rules[1].url_blacklist[0] == "/checkout",
                "second rule url blacklist loaded") &&
         expect(cfg.access_rules[1].url_category_blacklist.size() == 1 &&
                    cfg.access_rules[1].url_category_blacklist[0] == "shopping",
                "second rule category blacklist loaded");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_defaults_and_invalid_values_fallback() && ok;
  ok = test_arrays_and_scalar_values_are_loaded() && ok;
  ok = test_access_rules_are_loaded_with_nested_arrays() && ok;
  if (ok) {
    std::cout << "All config tests passed\n";
    return 0;
  }
  return 1;
}
