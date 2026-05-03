#pragma once

#include <cstdint>
#include <string>

namespace openscanproxy::config {

// 应用全局配置结构体，从 JSON 文件加载
struct AppConfig {
  // --- 代理服务器 ---
  std::string proxy_listen_host{"0.0.0.0"};
  uint16_t proxy_listen_port{8080};

  // --- 管理后台 ---
  std::string admin_listen_host{"127.0.0.1"};
  uint16_t admin_listen_port{9090};
  std::string admin_static_dir{"./web/dist"};

  // --- TLS MITM ---
  std::string ca_cert_path{"./certs/ca.crt"};
  std::string ca_key_path{"./certs/ca.key"};
  bool tls_leaf_cache_enabled{true};
  std::string tls_leaf_cache_dir{"./certs/cache"};

  // --- 扫描器 ---
  std::string scanner_type{"mock"};
  std::string clamav_mode{"unix"};
  std::string clamav_unix_socket{"/var/run/clamav/clamd.ctl"};
  std::string clamav_host{"127.0.0.1"};
  uint16_t clamav_port{3310};

  // --- 日志 ---
  std::string audit_log_path{"./logs/audit.jsonl"};
  std::size_t audit_recent_limit{500};
  std::string app_log_path{"./logs/app.log"};
  std::string app_log_level{"info"};
  std::size_t app_log_max_files{5};
  std::size_t app_log_max_size_mb{10};

  // --- Portal 认证 ---
  std::string proxy_auth_portal_listen_host{"127.0.0.1"};
  uint16_t proxy_auth_portal_listen_port{9091};
  std::string proxy_auth_cookie_name{"osp_proxy_auth"};
  std::string proxy_auth_insecure_cookie_name{"osp_proxy_auth_insecure"};
  std::string proxy_auth_portal_cookie_name{"osp_portal_session"};
  std::string proxy_auth_portal_session_file{"./configs/portal_sessions.json"};
  std::string proxy_auth_client_cache_file{"./configs/portal_client_auth_cache.json"};
  std::uint64_t proxy_auth_token_ttl_sec{120};
  std::uint64_t proxy_auth_portal_session_ttl_sec{3600};
  std::string proxy_auth_signing_key{"change-me"};

  // --- URL 分类 ---
  std::string domain_category_data_file{"./configs/domain_categories.csv"};

  // --- 数据库 ---
  std::string db_host{"127.0.0.1"};
  uint16_t db_port{5432};
  std::string db_name{"openscanproxy"};
  std::string db_user{"osp"};
  std::string db_password{"osp123"};
};

// 配置加载器，从 JSON 文件读取并解析为 AppConfig
class ConfigLoader {
 public:
  static AppConfig load_from_file(const std::string& path);
};

}  // namespace openscanproxy::config
