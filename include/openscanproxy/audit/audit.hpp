#pragma once

#include "openscanproxy/core/types.hpp"

#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace openscanproxy::audit {

struct AuditEvent {
  std::string event_type{"scan"};
  std::string timestamp;
  std::string client_addr;
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
  explicit AuditLogger(std::string log_path, std::size_t recent_limit = 500);
  void write(const AuditEvent& event);
  std::vector<AuditEvent> latest(std::size_t n) const;

 private:
  std::string to_json_line(const AuditEvent& e) const;

  std::string log_path_;
  std::size_t recent_limit_{500};
  mutable std::mutex mu_;
  std::deque<AuditEvent> recent_;
};

}  // namespace openscanproxy::audit
