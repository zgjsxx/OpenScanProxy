#pragma once

#include "openscanproxy/core/types.hpp"

#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace openscanproxy::audit {

// 审计事件结构体，记录一次请求/扫描的完整信息
struct AuditEvent {
  std::string event_type{"scan"};   // 事件类型：scan（扫描）、access（访问）、auth（认证）
  std::string timestamp;            // ISO 8601 时间戳
  std::string client_addr;          // 客户端地址（IP:端口）
  std::string user;                 // 认证用户名（未认证时为 "-"）
  std::string host;                 // 目标主机名
  std::string url;                  // 请求 URL
  std::string url_category;         // URL 分类标签
  std::string method;               // HTTP 方法（GET/POST/CONNECT 等）
  int status_code{0};               // HTTP 响应状态码
  std::uint64_t latency_ms{0};      // 请求处理耗时（毫秒）
  std::size_t bytes_in{0};          // 入站字节数
  std::size_t bytes_out{0};         // 出站字节数
  std::string rule_hit;             // 匹配的策略规则名
  std::string decision_source;      // 决策来源（策略名/扫描器名）
  bool https_mitm{false};           // 是否经过 HTTPS MITM 解密
  std::string filename;             // 提取的文件名（扫描事件）
  std::size_t file_size{0};         // 文件大小
  std::string mime;                 // 文件 MIME 类型
  std::string sha256;               // 文件 SHA-256 哈希
  std::string scanner;              // 扫描器名称
  std::string result;               // 扫描结果（Clean/Infected 等）
  std::string signature;            // 检测到的威胁签名
  std::string action;               // 最终动作（allow/block/redirect/log）
};

// 审计日志记录器，将事件写入 JSONL 文件并维护最近事件的内存队列
class AuditLogger {
 public:
  // 构造：指定日志文件路径和内存中保留的最近事件数量
  explicit AuditLogger(std::string log_path, std::size_t recent_limit = 500);
  // 写入一条审计事件（同时写入文件和内存队列）
  void write(const AuditEvent& event);
  // 获取最近 N 条事件（供管理 API 使用）
  std::vector<AuditEvent> latest(std::size_t n) const;

 private:
  // 将审计事件序列化为 JSONL 单行
  std::string to_json_line(const AuditEvent& e) const;

  std::string log_path_;           // 日志文件路径
  std::size_t recent_limit_{500};  // 内存队列容量上限
  mutable std::mutex mu_;          // 线程安全锁
  std::deque<AuditEvent> recent_;  // 最近事件的内存队列
};

}  // namespace openscanproxy::audit
