#pragma once

#include "openscanproxy/policy/policy.hpp"

#include <memory>
#include <string>

// Forward-declare libpq types to avoid exposing libpq headers in this header
struct pg_conn;
typedef struct pg_conn PGconn;

namespace openscanproxy::policy {

// PostgreSQL-backed persistence for policy configuration (lists, rules, scan settings)
class PolicyStore {
 public:
  explicit PolicyStore(const std::string& conninfo);
  ~PolicyStore();

  PolicyStore(const PolicyStore&) = delete;
  PolicyStore& operator=(const PolicyStore&) = delete;

  // Initialize tables if they don't exist
  bool init_db();

  // Full policy load/save (for /api/access-policy)
  PolicyConfig load_policy();
  bool save_policy(const PolicyConfig& cfg);

  // Scan policy only (for /api/policy)
  struct ScanPolicy {
    bool fail_open{true};
    bool block_suspicious{false};
    bool scan_upload{true};
    bool scan_download{true};
    std::size_t max_scan_file_size{5 * 1024 * 1024};
    std::uint64_t scan_timeout_ms{5000};
    std::vector<std::string> allowed_mime;
    std::vector<std::string> allowed_extensions;
  };
  ScanPolicy load_scan_policy();
  bool save_scan_policy(const ScanPolicy& sp);

  // Check if the database has been initialized (has policy data)
  bool has_policy_data();

  // Auth config (for /api/auth-config)
  struct AuthConfig {
    bool enable_proxy_auth{false};
    std::string proxy_auth_mode{"basic"};
    bool enable_https_mitm{false};
  };
  bool has_auth_config_data();
  AuthConfig load_auth_config();
  bool save_auth_config(bool enable, const std::string& mode, bool enable_mitm);

 private:
  std::string pq_escape_literal(const std::string& s);
  std::string pq_escape_identifier(const std::string& s);
  bool exec_simple(const std::string& sql);
  std::string query_one_string(const std::string& sql, const std::string& field);
  std::vector<std::string> query_string_list(const std::string& sql);

  PGconn* conn_{nullptr};
};

}  // namespace openscanproxy::policy
