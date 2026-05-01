#pragma once

#include "openscanproxy/policy/policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace openscanproxy::config {

// 应用全局配置结构体，从 JSON 文件加载
struct AppConfig {
  // --- 代理服务器 ---
  std::string proxy_listen_host{"0.0.0.0"};   // 代理监听地址
  uint16_t proxy_listen_port{8080};            // 代理监听端口

  // --- 管理后台 ---
  std::string admin_listen_host{"127.0.0.1"};  // 管理后台监听地址
  uint16_t admin_listen_port{9090};            // 管理后台监听端口
  std::string admin_static_dir{"./web/dist"};  // 管理后台静态资源目录

  // --- TLS MITM ---
  std::string ca_cert_path{"./certs/ca.crt"};  // CA 证书路径
  std::string ca_key_path{"./certs/ca.key"};   // CA 私钥路径
  bool enable_https_mitm{false};               // 是否启用 HTTPS MITM 解密
  bool tls_leaf_cache_enabled{true};           // 是否缓存 TLS 叶子证书
  std::string tls_leaf_cache_dir{"./certs/cache"}; // 叶子证书缓存目录

  // --- 扫描 ---
  bool scan_upload{true};                      // 是否扫描上传文件
  bool scan_download{true};                    // 是否扫描下载文件
  std::size_t max_scan_file_size{5 * 1024 * 1024}; // 单文件最大扫描大小（5MB）
  std::vector<std::string> allowed_mime;       // 允许扫描的 MIME 类型列表
  std::vector<std::string> allowed_extensions; // 允许扫描的文件扩展名列表

  // --- 访问策略 ---
  std::vector<std::string> domain_whitelist;   // 域名白名单
  std::vector<std::string> domain_blacklist;   // 域名黑名单
  std::vector<std::string> user_whitelist;     // 用户白名单
  std::vector<std::string> user_blacklist;     // 用户黑名单
  std::vector<std::string> url_whitelist;      // URL 白名单
  std::vector<std::string> url_blacklist;      // URL 黑名单
  std::vector<std::string> url_category_whitelist; // URL 分类白名单
  std::vector<std::string> url_category_blacklist; // URL 分类黑名单
  std::vector<policy::AccessRule> access_rules; // 自定义访问规则列表
  std::string default_access_action{"allow"};  // 默认访问动作（allow/block）

  // --- 扫描策略 ---
  std::uint64_t scan_timeout_ms{5000};         // 扫描超时时间（毫秒）
  std::string policy_mode{"fail-open"};        // 策略模式：fail-open（扫描失败时放行）或 fail-close（扫描失败时阻止）
  std::string suspicious_action{"log"};        // 可疑文件的处理动作（log/block）

  // --- 扫描器 ---
  std::string scanner_type{"mock"};            // 扫描器类型：mock 或 clamav
  std::string clamav_mode{"unix"};             // ClamAV 连接模式：unix 或 tcp
  std::string clamav_unix_socket{"/var/run/clamav/clamd.ctl"}; // ClamAV Unix socket 路径
  std::string clamav_host{"127.0.0.1"};        // ClamAV TCP 地址
  uint16_t clamav_port{3310};                  // ClamAV TCP 端口

  // --- 日志 ---
  std::string audit_log_path{"./logs/audit.jsonl"}; // 审计日志文件路径（JSONL 格式）
  std::size_t audit_recent_limit{500};         // 内存中保留的最近审计事件数
  std::string app_log_path{"./logs/app.log"};  // 应用日志文件路径
  std::string app_log_level{"info"};           // 应用日志最低级别
  std::size_t app_log_max_files{5};            // 应用日志最大文件数
  std::size_t app_log_max_size_mb{10};         // 应用日志单文件最大大小（MB）

  // --- 管理后台认证 ---
  std::string admin_user{"admin"};             // 管理后台用户名
  std::string admin_password{"admin123"};      // 管理后台密码

  // --- 代理认证 ---
  bool enable_proxy_auth{false};               // 是否启用代理认证
  std::string proxy_auth_mode{"basic"};        // 认证模式：basic、portal 或 other（同时启用两种）
  std::string proxy_auth_user{"proxy"};        // 默认代理认证用户名
  std::string proxy_auth_password{"proxy123"}; // 默认代理认证密码
  std::string proxy_users_file{"./configs/proxy_users.json"}; // 持久化用户存储文件

  // --- Portal 认证 ---
  std::string proxy_auth_portal_listen_host{"127.0.0.1"}; // Portal HTTPS 服务器地址
  uint16_t proxy_auth_portal_listen_port{9091}; // Portal HTTPS 服务器端口
  std::string proxy_auth_cookie_name{"osp_proxy_auth"}; // HTTPS 域级认证 Cookie 名
  std::string proxy_auth_insecure_cookie_name{"osp_proxy_auth_insecure"}; // HTTP 域级认证 Cookie 名
  std::string proxy_auth_portal_cookie_name{"osp_portal_session"}; // Portal 会话 Cookie 名
  std::string proxy_auth_portal_session_file{"./configs/portal_sessions.json"}; // Portal 会话持久化文件
  std::string proxy_auth_client_cache_file{"./configs/portal_client_auth_cache.json"}; // 客户端 IP 认证缓存文件
  std::uint64_t proxy_auth_token_ttl_sec{120}; // 一次性域认证令牌 TTL（秒）
  std::uint64_t proxy_auth_portal_session_ttl_sec{3600}; // Portal 会话 TTL（秒）
  std::string proxy_auth_signing_key{"change-me"}; // 域级 Cookie 签名密钥（生产环境必须替换）

  // --- URL 分类 ---
  std::string domain_category_data_file{"./configs/domain_categories.csv"}; // 域名分类数据文件

  // --- 数据库 ---
  std::string db_host{"127.0.0.1"};           // 数据库主机
  uint16_t db_port{5432};                      // 数据库端口
  std::string db_name{"openscanproxy"};        // 数据库名称
  std::string db_user{"osp"};                  // 数据库用户名
  std::string db_password{"osp123"};           // 数据库密码
};

// 配置加载器，从 JSON 文件读取并解析为 AppConfig
class ConfigLoader {
 public:
  static AppConfig load_from_file(const std::string& path);
};

}  // namespace openscanproxy::config
