#pragma once

#include <atomic>
#include <string>

namespace openscanproxy::stats {

struct Snapshot {
  uint64_t total_requests{0};
  uint64_t https_mitm_requests{0};
  uint64_t scanned_files{0};
  uint64_t clean{0};
  uint64_t infected{0};
  uint64_t suspicious{0};
  uint64_t blocked{0};
  uint64_t scanner_error{0};
};

class StatsRegistry {
 public:
  void inc_total_requests() { ++total_requests_; }
  void inc_https_mitm_requests() { ++https_mitm_requests_; }
  void inc_scanned_files() { ++scanned_files_; }
  void inc_clean() { ++clean_; }
  void inc_infected() { ++infected_; }
  void inc_suspicious() { ++suspicious_; }
  void inc_blocked() { ++blocked_; }
  void inc_scanner_error() { ++scanner_error_; }

  Snapshot snapshot() const;
  std::string to_metrics_text() const;

 private:
  std::atomic<uint64_t> total_requests_{0};
  std::atomic<uint64_t> https_mitm_requests_{0};
  std::atomic<uint64_t> scanned_files_{0};
  std::atomic<uint64_t> clean_{0};
  std::atomic<uint64_t> infected_{0};
  std::atomic<uint64_t> suspicious_{0};
  std::atomic<uint64_t> blocked_{0};
  std::atomic<uint64_t> scanner_error_{0};
};

}  // namespace openscanproxy::stats
