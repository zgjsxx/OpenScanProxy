#include "openscanproxy/audit/audit.hpp"

#include "openscanproxy/core/util.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace openscanproxy::audit {

AuditLogger::AuditLogger(std::string log_path, std::size_t recent_limit)
    : log_path_(std::move(log_path)), recent_limit_(recent_limit > 0 ? recent_limit : 1) {
  std::filesystem::create_directories(std::filesystem::path(log_path_).parent_path());
}

void AuditLogger::write(const AuditEvent& event) {
  std::lock_guard<std::mutex> lk(mu_);
  std::ofstream ofs(log_path_, std::ios::app);
  ofs << to_json_line(event) << "\n";
  recent_.push_back(event);
  if (recent_.size() > recent_limit_) recent_.pop_front();
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
