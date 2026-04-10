#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace openscanproxy::config {

struct AppConfig {
  std::string proxy_listen_host{"0.0.0.0"};
  uint16_t proxy_listen_port{8080};
  std::string admin_listen_host{"127.0.0.1"};
  uint16_t admin_listen_port{9090};
  std::string admin_static_dir{"./web/dist"};

  std::string ca_cert_path{"./certs/ca.crt"};
  std::string ca_key_path{"./certs/ca.key"};
  bool enable_https_mitm{false};

  bool scan_upload{true};
  bool scan_download{true};
  std::size_t max_scan_file_size{5 * 1024 * 1024};
  std::vector<std::string> allowed_mime;
  std::vector<std::string> allowed_extensions;

  std::uint64_t scan_timeout_ms{5000};
  std::string policy_mode{"fail-open"};
  std::string suspicious_action{"log"};

  std::string scanner_type{"mock"};
  std::string clamav_mode{"unix"};
  std::string clamav_unix_socket{"/var/run/clamav/clamd.ctl"};
  std::string clamav_host{"127.0.0.1"};
  uint16_t clamav_port{3310};

  std::string audit_log_path{"./logs/audit.jsonl"};
  std::string admin_user{"admin"};
  std::string admin_password{"admin123"};
};

class ConfigLoader {
 public:
  static AppConfig load_from_file(const std::string& path);
};

}  // namespace openscanproxy::config
