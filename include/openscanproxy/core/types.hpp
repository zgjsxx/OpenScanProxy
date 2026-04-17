#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openscanproxy::core {

// 数据传输方向：上传（客户端→服务器）或下载（服务器→客户端）
enum class Direction { Upload, Download };

// 扫描结果状态：干净、感染、可疑、错误
enum class ScanStatus { Clean, Infected, Suspicious, Error };

// 策略决策动作：允许、阻止、仅记录
enum class Action { Allow, Block, LogOnly };

// 从 HTTP 请求/响应中提取的待扫描文件
struct ExtractedFile {
  std::string filename;          // 文件名
  std::string mime;              // MIME 类型
  std::vector<uint8_t> bytes;    // 文件内容
  Direction direction{Direction::Upload};  // 传输方向
  std::string source_url;        // 来源 URL
  std::string source_host;       // 来源主机
  std::map<std::string, std::string> metadata;  // 附加元数据
};

// 扫描器返回的结果
struct ScanResult {
  ScanStatus status{ScanStatus::Error};  // 扫描状态
  std::string scanner_name;    // 扫描器名称
  std::string signature;       // 检测到的威胁签名
  std::uint64_t elapsed_ms{0}; // 扫描耗时（毫秒）
  std::map<std::string, std::string> metadata;  // 扫描器附加信息
  std::string error;           // 错误描述（仅当 status==Error 时有意义）
};

}  // namespace openscanproxy::core
