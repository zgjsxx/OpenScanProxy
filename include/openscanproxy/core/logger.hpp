#pragma once

#include <cstddef>
#include <string>

namespace openscanproxy::core {

enum class LogLevel {
  Debug = 0,
  Info = 1,
  Warn = 2,
  Error = 3,
};

class AppLogger {
 public:
  static AppLogger& instance();

  void configure(std::string log_path, std::string level, std::size_t max_files, std::size_t max_file_size_mb);
  void log(LogLevel level, const std::string& message);
  bool should_log(LogLevel level) const;

 private:
  AppLogger() = default;

  std::string line_prefix(LogLevel level) const;
  std::string level_to_string(LogLevel level) const;
  std::string today_utc() const;
  std::string file_path_for(std::size_t index) const;
  void ensure_target_file(std::size_t expected_write_size);
  void rotate_window();

  std::string log_path_{"./logs/app.log"};
  LogLevel min_level_{LogLevel::Info};
  std::size_t max_files_{5};
  std::size_t max_file_size_bytes_{10 * 1024 * 1024};
  std::string current_date_;
  std::size_t current_index_{1};
};

inline AppLogger& app_logger() { return AppLogger::instance(); }

}  // namespace openscanproxy::core
