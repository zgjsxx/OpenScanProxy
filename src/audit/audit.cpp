#include "openscanproxy/audit/audit.hpp"

#include "openscanproxy/core/util.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace openscanproxy::audit {

AuditLogger::AuditLogger(std::string log_path, std::size_t recent_limit, std::size_t max_file_size_bytes, std::size_t max_files)
    : log_path_(std::move(log_path)),
      recent_limit_(recent_limit > 0 ? recent_limit : 1),
      max_file_size_bytes_(max_file_size_bytes > 0 ? max_file_size_bytes : 1),
      max_files_(max_files > 0 ? max_files : 1) {
  std::filesystem::create_directories(std::filesystem::path(log_path_).parent_path());
}

void AuditLogger::write(const AuditEvent& event) {
  std::lock_guard<std::mutex> lk(mu_);
  cleanup_old_files();
  std::ofstream ofs(current_log_file_path(), std::ios::app);
  ofs << to_json_line(event) << "\n";
  recent_.push_back(event);
  if (recent_.size() > recent_limit_) recent_.pop_front();
}

std::string AuditLogger::date_suffix_utc() {
  std::time_t now = std::time(nullptr);
  std::tm tm {};
#if defined(_WIN32)
  gmtime_s(&tm, &now);
#else
  gmtime_r(&now, &tm);
#endif
  std::ostringstream os;
  os << std::put_time(&tm, "%Y%m%d");
  return os.str();
}

bool AuditLogger::has_expected_extension(const std::filesystem::path& path, const std::string& ext) {
  return ext.empty() ? !path.has_extension() : path.extension() == ext;
}

std::string AuditLogger::current_log_file_path() const {
  const std::filesystem::path base(log_path_);
  const auto dir = base.parent_path();
  const auto stem = base.stem().string();
  const auto ext = base.extension().string();
  const auto today = date_suffix_utc();
  std::filesystem::create_directories(dir);

  std::vector<std::filesystem::path> candidates;
  const std::string prefix = stem + "-" + today + "-";
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (!entry.is_regular_file()) continue;
    const auto& p = entry.path();
    if (!has_expected_extension(p, ext)) continue;
    const auto name = p.stem().string();
    if (name.rfind(prefix, 0) != 0) continue;
    candidates.push_back(p);
  }

  int max_idx = -1;
  std::filesystem::path latest_path;
  for (const auto& p : candidates) {
    const auto name = p.stem().string();
    const auto idx_str = name.substr(prefix.size());
    try {
      int idx = std::stoi(idx_str);
      if (idx > max_idx) {
        max_idx = idx;
        latest_path = p;
      }
    } catch (...) {
    }
  }

  if (max_idx >= 0) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(latest_path, ec);
    if (!ec && sz < max_file_size_bytes_) return latest_path.string();
    return (dir / (prefix + std::to_string(max_idx + 1) + ext)).string();
  }
  return (dir / (prefix + "0" + ext)).string();
}

void AuditLogger::cleanup_old_files() const {
  const std::filesystem::path base(log_path_);
  const auto dir = base.parent_path();
  const auto stem = base.stem().string();
  const auto ext = base.extension().string();
  if (!std::filesystem::exists(dir)) return;

  std::vector<std::filesystem::directory_entry> entries;
  const std::string prefix = stem + "-";
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (!entry.is_regular_file()) continue;
    const auto& p = entry.path();
    if (!has_expected_extension(p, ext)) continue;
    const auto name = p.stem().string();
    if (name.rfind(prefix, 0) != 0) continue;
    entries.push_back(entry);
  }
  if (entries.size() <= max_files_) return;

  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    std::error_code ec_a;
    std::error_code ec_b;
    auto ta = std::filesystem::last_write_time(a.path(), ec_a);
    auto tb = std::filesystem::last_write_time(b.path(), ec_b);
    if (ec_a && ec_b) return a.path().string() < b.path().string();
    if (ec_a) return true;
    if (ec_b) return false;
    return ta < tb;
  });

  const auto remove_count = entries.size() - max_files_;
  for (std::size_t i = 0; i < remove_count; ++i) {
    std::error_code ec;
    std::filesystem::remove(entries[i].path(), ec);
  }
}

std::vector<AuditEvent> AuditLogger::latest(std::size_t n) const {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<AuditEvent> out;
  auto start = recent_.size() > n ? recent_.size() - n : 0;
  for (size_t i = start; i < recent_.size(); ++i) out.push_back(recent_[i]);
  return out;
}

std::string AuditLogger::to_json_line(const AuditEvent& e) const {
  std::ostringstream os;
  os << "{";
  os << "\"event_type\":\"" << core::json_escape(e.event_type) << "\",";
  os << "\"timestamp\":\"" << core::json_escape(e.timestamp) << "\",";
  os << "\"client_addr\":\"" << core::json_escape(e.client_addr) << "\",";
  os << "\"user\":\"" << core::json_escape(e.user) << "\",";
  os << "\"host\":\"" << core::json_escape(e.host) << "\",";
  os << "\"url\":\"" << core::json_escape(e.url) << "\",";
  os << "\"method\":\"" << core::json_escape(e.method) << "\",";
  os << "\"status_code\":" << e.status_code << ",";
  os << "\"latency_ms\":" << e.latency_ms << ",";
  os << "\"bytes_in\":" << e.bytes_in << ",";
  os << "\"bytes_out\":" << e.bytes_out << ",";
  os << "\"rule_hit\":\"" << core::json_escape(e.rule_hit) << "\",";
  os << "\"decision_source\":\"" << core::json_escape(e.decision_source) << "\",";
  os << "\"https_mitm\":" << (e.https_mitm ? "true" : "false") << ",";
  os << "\"filename\":\"" << core::json_escape(e.filename) << "\",";
  os << "\"file_size\":" << e.file_size << ",";
  os << "\"mime\":\"" << core::json_escape(e.mime) << "\",";
  os << "\"sha256\":\"" << core::json_escape(e.sha256) << "\",";
  os << "\"scanner\":\"" << core::json_escape(e.scanner) << "\",";
  os << "\"result\":\"" << core::json_escape(e.result) << "\",";
  os << "\"signature\":\"" << core::json_escape(e.signature) << "\",";
  os << "\"action\":\"" << core::json_escape(e.action) << "\"";
  os << "}";
  return os.str();
}

}  // namespace openscanproxy::audit
