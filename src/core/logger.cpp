#include "openscanproxy/core/logger.hpp"

#include "openscanproxy/core/util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>

namespace openscanproxy::core {
namespace {
std::mutex g_logger_mu;

LogLevel parse_level(const std::string& level) {
  auto lv = to_lower(level);
  if (lv == "debug") return LogLevel::Debug;
  if (lv == "warn" || lv == "warning") return LogLevel::Warn;
  if (lv == "error") return LogLevel::Error;
  return LogLevel::Info;
}

}  // namespace

AppLogger& AppLogger::instance() {
  static AppLogger inst;
  return inst;
}

void AppLogger::configure(std::string log_path, std::string level, std::size_t max_files, std::size_t max_file_size_mb) {
  std::lock_guard<std::mutex> lk(g_logger_mu);
  log_path_ = std::move(log_path);
  min_level_ = parse_level(level);
  max_files_ = max_files == 0 ? 1 : max_files;
  if (max_files_ > 5) max_files_ = 5;
  max_file_size_bytes_ = (max_file_size_mb == 0 ? 10 : max_file_size_mb) * 1024 * 1024;
  current_date_.clear();
  current_index_ = 1;
  auto dir = std::filesystem::path(log_path_).parent_path();
  if (!dir.empty()) std::filesystem::create_directories(dir);
}

bool AppLogger::should_log(LogLevel level) const { return static_cast<int>(level) >= static_cast<int>(min_level_); }

std::string AppLogger::level_to_string(LogLevel level) const {
  switch (level) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info: return "INFO";
    case LogLevel::Warn: return "WARN";
    case LogLevel::Error: return "ERROR";
  }
  return "INFO";
}

std::string AppLogger::line_prefix(LogLevel level) const {
  std::ostringstream os;
  os << "[" << now_iso8601() << "]"
     << "[" << level_to_string(level) << "] ";
  return os.str();
}

std::string AppLogger::today_utc() const {
  auto now = now_iso8601();
  if (now.size() < 10) return "19700101";
  return now.substr(0, 4) + now.substr(5, 2) + now.substr(8, 2);
}

std::string AppLogger::file_path_for(std::size_t index) const {
  auto p = std::filesystem::path(log_path_);
  auto stem = p.stem().string();
  auto ext = p.extension().string();
  if (stem.empty()) stem = "app";
  std::ostringstream name;
  name << stem << "-" << current_date_ << "-" << index << ext;
  auto out = p.parent_path() / name.str();
  return out.string();
}

void AppLogger::rotate_window() {
  auto first = file_path_for(1);
  std::error_code ec;
  std::filesystem::remove(first, ec);
  for (std::size_t i = 2; i <= max_files_; ++i) {
    auto from = file_path_for(i);
    auto to = file_path_for(i - 1);
    if (std::filesystem::exists(from)) {
      std::filesystem::remove(to, ec);
      std::filesystem::rename(from, to, ec);
    }
  }
  current_index_ = max_files_;
}

void AppLogger::ensure_target_file(std::size_t expected_write_size) {
  auto today = today_utc();
  if (current_date_ != today) {
    current_date_ = today;
    current_index_ = 1;
  }

  while (true) {
    auto path = file_path_for(current_index_);
    std::size_t current_size = 0;
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) current_size = static_cast<std::size_t>(std::filesystem::file_size(path, ec));
    if (current_size + expected_write_size <= max_file_size_bytes_) return;
    if (current_index_ < max_files_) {
      ++current_index_;
      continue;
    }
    rotate_window();
    return;
  }
}

void AppLogger::log(LogLevel level, const std::string& message) {
  if (!should_log(level)) return;

  auto line = line_prefix(level) + message + "\n";

  std::lock_guard<std::mutex> lk(g_logger_mu);
  ensure_target_file(line.size());
  auto path = file_path_for(current_index_);

  std::ofstream ofs(path, std::ios::app);
  if (ofs) ofs << line;

  if (level == LogLevel::Error || level == LogLevel::Warn) {
    std::cerr << line;
  } else {
    std::cout << line;
  }
}

}  // namespace openscanproxy::core
