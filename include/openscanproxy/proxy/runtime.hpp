#pragma once

#include "openscanproxy/audit/audit.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/extractor/extractor.hpp"
#include "openscanproxy/policy/policy.hpp"
#include "openscanproxy/scanner/scanner.hpp"
#include "openscanproxy/stats/stats.hpp"
#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace openscanproxy::proxy {

class ProxyAuthStore {
 public:
  explicit ProxyAuthStore(const config::AppConfig& cfg) : enabled_(cfg.enable_proxy_auth), users_file_(cfg.proxy_users_file) {
    if (!cfg.proxy_auth_user.empty()) users_[cfg.proxy_auth_user] = cfg.proxy_auth_password;
    load_from_file_locked();
  }

  bool enabled() const { return enabled_; }
  void set_enabled(bool enabled) { enabled_ = enabled; }

  bool authenticate(const std::string& user, const std::string& password) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = users_.find(user);
    return it != users_.end() && it->second == password;
  }

  bool upsert_user(const std::string& user, const std::string& password) {
    if (user.empty() || password.empty()) return false;
    std::lock_guard<std::mutex> lk(mu_);
    users_[user] = password;
    persist_to_file_locked();
    return true;
  }

  std::vector<std::string> list_users() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::string> out;
    out.reserve(users_.size());
    for (const auto& [u, _] : users_) out.push_back(u);
    return out;
  }

 private:
  static std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(c); break;
      }
    }
    return out;
  }

  void load_from_file_locked() {
    if (users_file_.empty() || !std::filesystem::exists(users_file_)) return;
    std::ifstream ifs(users_file_);
    if (!ifs) return;
    std::stringstream ss;
    ss << ifs.rdbuf();
    auto text = ss.str();
    std::regex item("\\{\\s*\\\"username\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\\s*,\\s*\\\"password\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"\\s*\\}");
    for (std::sregex_iterator it(text.begin(), text.end(), item), end; it != end; ++it) {
      auto username = (*it)[1].str();
      auto password = (*it)[2].str();
      if (!username.empty()) users_[username] = password;
    }
  }

  void persist_to_file_locked() const {
    if (users_file_.empty()) return;
    std::filesystem::create_directories(std::filesystem::path(users_file_).parent_path());
    std::ofstream ofs(users_file_, std::ios::trunc);
    if (!ofs) return;
    std::vector<std::string> usernames;
    usernames.reserve(users_.size());
    for (const auto& [u, _] : users_) usernames.push_back(u);
    std::sort(usernames.begin(), usernames.end());
    ofs << "{\"users\":[";
    for (std::size_t i = 0; i < usernames.size(); ++i) {
      if (i) ofs << ",";
      const auto& u = usernames[i];
      ofs << "{\"username\":\"" << json_escape(u) << "\",\"password\":\"" << json_escape(users_.at(u)) << "\"}";
    }
    ofs << "]}";
  }

  bool enabled_{false};
  std::string users_file_;
  mutable std::mutex mu_;
  std::unordered_map<std::string, std::string> users_;
};

struct Runtime {
  config::AppConfig config;
  ProxyAuthStore proxy_auth;
  std::unique_ptr<scanner::IScanner> scanner;
  scanner::ScanContext scan_ctx;
  policy::PolicyEngine policy;
  extractor::FileExtractor extractor;
  audit::AuditLogger audit;
  stats::StatsRegistry stats;
  tlsmitm::TLSMitmEngine tls_mitm;

  explicit Runtime(config::AppConfig cfg)
      : config(std::move(cfg)),
        proxy_auth(config),
        policy(policy::PolicyConfig{config.policy_mode != "fail-close",
                                    config.suspicious_action == "block",
                                    config.domain_whitelist,
                                    config.domain_blacklist,
                                    config.user_whitelist,
                                    config.user_blacklist,
                                    config.url_whitelist,
                                    config.url_blacklist,
                                    policy::access_action_from_string(config.default_access_action)}),
        audit(config.audit_log_path,
              config.audit_recent_limit,
              config.audit_max_file_size_bytes,
              config.audit_max_files) {}
};

}  // namespace openscanproxy::proxy
