#pragma once

#include <cstddef>
#include <string>

namespace openscanproxy::core {

// 日志级别：调试、信息、警告、错误
enum class LogLevel {
  Debug = 0,
  Info = 1,
  Warn = 2,
  Error = 3,
};

// 应用日志记录器（单例模式），支持文件滚动和按级别过滤
class AppLogger {
 public:
  // 获取全局单例实例
  static AppLogger& instance();

  // 配置日志：路径、最低级别、最大文件数、单文件最大大小（MB）
  void configure(std::string log_path, std::string level, std::size_t max_files, std::size_t max_file_size_mb);
  // 写入一条日志
  void log(LogLevel level, const std::string& message);
  // 判断指定级别是否达到最低输出阈值
  bool should_log(LogLevel level) const;

 private:
  AppLogger() = default;

  // 生成日志行前缀（时间戳+级别）
  std::string line_prefix(LogLevel level) const;
  // 将日志级别转为字符串
  std::string level_to_string(LogLevel level) const;
  // 获取当前 UTC 日期字符串
  std::string today_utc() const;
  // 根据滚动索引生成文件路径
  std::string file_path_for(std::size_t index) const;
  // 确保当前日志文件有足够空间，必要时执行滚动
  void ensure_target_file(std::size_t expected_write_size);
  // 执行日志文件滚动（按日期和大小）
  void rotate_window();

  std::string log_path_{"./logs/app.log"};     // 日志文件路径
  LogLevel min_level_{LogLevel::Info};          // 最低输出级别
  std::size_t max_files_{5};                    // 最大保留文件数
  std::size_t max_file_size_bytes_{10 * 1024 * 1024};  // 单文件最大字节
  std::string current_date_;                    // 当前日期（用于按日期滚动）
  std::size_t current_index_{1};               // 当前文件滚动索引
};

// 全局日志访问快捷函数
inline AppLogger& app_logger() { return AppLogger::instance(); }

}  // namespace openscanproxy::core
