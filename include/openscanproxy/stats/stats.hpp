#pragma once

#include <atomic>
#include <string>

namespace openscanproxy::stats {

// 统计数据快照，用于一次性获取所有计数器的当前值
struct Snapshot {
  uint64_t total_requests{0};      // 总请求数
  uint64_t https_mitm_requests{0}; // HTTPS MITM 解密请求数
  uint64_t scanned_files{0};       // 已扫描文件数
  uint64_t clean{0};               // 扫描结果为干净的文件数
  uint64_t infected{0};            // 扫描结果为感染的文件数
  uint64_t suspicious{0};          // 扫描结果为可疑的文件数
  uint64_t blocked{0};             // 被策略阻止的请求数
  uint64_t scanner_error{0};       // 扫描器出错的次数
};

// 统计计数器注册表，所有计数器使用原子操作保证线程安全
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

  // 获取当前所有计数器的快照
  Snapshot snapshot() const;
  // 将统计数据格式化为文本（供管理 API 使用）
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
