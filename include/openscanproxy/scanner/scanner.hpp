#pragma once

#include "openscanproxy/core/types.hpp"

#include <memory>

namespace openscanproxy::scanner {

// 扫描上下文，传递扫描超时等参数
struct ScanContext {
  std::uint64_t timeout_ms{5000};
  std::size_t max_scan_file_size{5 * 1024 * 1024};
};

// 扫描器接口（抽象基类）
class IScanner {
 public:
  virtual ~IScanner() = default;
  // 扫描器名称
  virtual const char* name() const = 0;
  // 对提取的文件执行扫描
  virtual core::ScanResult scan(const core::ExtractedFile& file, const ScanContext& ctx) = 0;
};

// 创建 Mock 扫描器（用于测试，总是返回 Clean）
std::unique_ptr<IScanner> create_mock_scanner();
// 创建 ClamAV 扫描器（支持 Unix socket 和 TCP 连接）
std::unique_ptr<IScanner> create_clamav_scanner(const std::string& mode, const std::string& unix_socket,
                                                const std::string& host, uint16_t port);

}  // namespace openscanproxy::scanner
