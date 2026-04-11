#pragma once

#include "openscanproxy/core/types.hpp"

#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace openscanproxy::audit {

struct AuditEvent {
  std::string event_type{"scan"};
  std::string timestamp;
  std::string client_addr;
  std::string user;
  std::string host;
  std::string url;
  std::string method;
  int status_code{0};
  std::uint64_t latency_ms{0};
  std::size_t bytes_in{0};
  std::size_t bytes_out{0};
  std::string rule_hit;
  std::string decision_source;
  bool https_mitm{false};
  std::string filename;
  std::size_t file_size{0};
  std::string mime;
  std::string sha256;
  std::string scanner;
  std::string result;
  std::string signature;
  std::string action;
};

class AuditLogger {
 public:
  explicit AuditLogger(std::string log_path,
                       std::size_t recent_limit = 500,
                       std::size_t max_file_size_bytes = 10 * 1024 * 1024,
                       std::size_t max_files = 5);
  void write(const AuditEvent& event);
  std::vector<AuditEvent> latest(std::size_t n) const;

 private:
  std::string current_log_file_path() const;
  static std::string date_suffix_utc();
  static bool has_expected_extension(const std::filesystem::path& path, const std::string& ext);
  void cleanup_old_files() const;
  std::string to_json_line(const AuditEvent& e) const;

  std::string log_path_;
  std::size_t recent_limit_{500};
  std::size_t max_file_size_bytes_{10 * 1024 * 1024};
  std::size_t max_files_{5};
  mutable std::mutex mu_;
  std::deque<AuditEvent> recent_;
};

}  // namespace openscanproxy::audit
