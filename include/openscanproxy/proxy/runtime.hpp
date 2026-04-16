#pragma once

#include "openscanproxy/audit/audit.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/core/util.hpp"
#include "openscanproxy/extractor/extractor.hpp"
#include "openscanproxy/policy/policy.hpp"
#include "openscanproxy/scanner/scanner.hpp"
#include "openscanproxy/stats/stats.hpp"
#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <memory>
#include <optional>
#include <random>
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

struct PortalSession {
  std::string username;
  std::chrono::system_clock::time_point expires_at;
  std::chrono::system_clock::time_point last_seen_at;
};

class PortalSessionStore {
 public:
  std::string create(const std::string& username, std::uint64_t ttl_sec) {
    if (username.empty()) return "";
    std::lock_guard<std::mutex> lk(mu_);
    auto id = random_token_locked(32);
    auto now = std::chrono::system_clock::now();
    sessions_[id] = PortalSession{username, now + std::chrono::seconds(ttl_sec), now};
    return id;
  }

  std::string lookup_user(const std::string& session_id) {
    if (session_id.empty()) return "";
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return "";
    auto now = std::chrono::system_clock::now();
    if (it->second.expires_at <= now) {
      sessions_.erase(it);
      return "";
    }
    it->second.last_seen_at = now;
    return it->second.username;
  }

  void destroy(const std::string& session_id) {
    std::lock_guard<std::mutex> lk(mu_);
    sessions_.erase(session_id);
  }

 private:
  std::string random_token_locked(std::size_t bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (std::size_t i = 0; i < bytes; ++i) {
      auto value = static_cast<unsigned int>(rng_() & 0xFF);
      out.push_back(kHex[(value >> 4) & 0xF]);
      out.push_back(kHex[value & 0xF]);
    }
    return out;
  }

  std::mutex mu_;
  std::unordered_map<std::string, PortalSession> sessions_;
  std::mt19937_64 rng_{std::random_device{}()};
};

struct DomainAuthToken {
  std::string username;
  std::string host;
  std::chrono::system_clock::time_point expires_at;
};

struct PortalClientAuth {
  std::string username;
  std::chrono::system_clock::time_point expires_at;
  std::chrono::system_clock::time_point last_seen_at;
};

class PortalClientAuthStore {
 public:
  void upsert(const std::string& client_ip, const std::string& username, std::uint64_t ttl_sec) {
    if (client_ip.empty() || username.empty()) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto now = std::chrono::system_clock::now();
    auto expires_at = now + std::chrono::seconds(ttl_sec);
    clients_[client_ip] = PortalClientAuth{username, expires_at, now};
    core::app_logger().log(core::LogLevel::Info,
                           "portal client-ip cache: upsert client_ip=" + client_ip +
                               " user=" + username +
                               " ttl_sec=" + std::to_string(ttl_sec) +
                               " expires_at=" + format_time_point(expires_at) +
                               " size=" + std::to_string(clients_.size()));
  }

  std::string lookup_user(const std::string& client_ip) {
    if (client_ip.empty()) return "";
    std::lock_guard<std::mutex> lk(mu_);
    auto it = clients_.find(client_ip);
    if (it == clients_.end()) {
      core::app_logger().log(core::LogLevel::Warn,
                             "portal client-ip cache: miss client_ip=" + client_ip +
                                 " size=" + std::to_string(clients_.size()));
      return "";
    }
    auto now = std::chrono::system_clock::now();
    if (it->second.expires_at <= now) {
      core::app_logger().log(core::LogLevel::Warn,
                             "portal client-ip cache: expired client_ip=" + client_ip +
                                 " user=" + it->second.username +
                                 " expires_at=" + format_time_point(it->second.expires_at) +
                                 " now=" + format_time_point(now));
      clients_.erase(it);
      core::app_logger().log(core::LogLevel::Info,
                             "portal client-ip cache: erase-expired client_ip=" + client_ip +
                                 " size=" + std::to_string(clients_.size()));
      return "";
    }
    it->second.last_seen_at = now;
    core::app_logger().log(core::LogLevel::Info,
                           "portal client-ip cache: hit client_ip=" + client_ip +
                               " user=" + it->second.username +
                               " expires_at=" + format_time_point(it->second.expires_at) +
                               " last_seen_at=" + format_time_point(it->second.last_seen_at));
    return it->second.username;
  }

  void destroy(const std::string& client_ip) {
    if (client_ip.empty()) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = clients_.find(client_ip);
    if (it == clients_.end()) {
      core::app_logger().log(core::LogLevel::Info,
                             "portal client-ip cache: destroy-miss client_ip=" + client_ip +
                                 " size=" + std::to_string(clients_.size()));
      return;
    }
    auto username = it->second.username;
    clients_.erase(it);
    core::app_logger().log(core::LogLevel::Info,
                           "portal client-ip cache: destroy client_ip=" + client_ip +
                               " user=" + username +
                               " size=" + std::to_string(clients_.size()));
  }

 private:
  static std::string format_time_point(const std::chrono::system_clock::time_point& tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) return "";
    return buf;
  }

  std::mutex mu_;
  std::unordered_map<std::string, PortalClientAuth> clients_;
};

class ProxyDomainTokenStore {
 public:
  std::string issue(const std::string& username, const std::string& host, std::uint64_t ttl_sec) {
    if (username.empty() || host.empty()) return "";
    std::lock_guard<std::mutex> lk(mu_);
    auto token = random_token_locked(24);
    tokens_[token] = DomainAuthToken{username, core::to_lower(host), std::chrono::system_clock::now() + std::chrono::seconds(ttl_sec)};
    return token;
  }

  std::string consume(const std::string& token, const std::string& host) {
    if (token.empty() || host.empty()) return "";
    std::lock_guard<std::mutex> lk(mu_);
    auto it = tokens_.find(token);
    if (it == tokens_.end()) return "";
    auto now = std::chrono::system_clock::now();
    auto expected_host = core::to_lower(host);
    if (it->second.expires_at <= now || it->second.host != expected_host) {
      tokens_.erase(it);
      return "";
    }
    auto username = it->second.username;
    tokens_.erase(it);
    return username;
  }

 private:
  std::string random_token_locked(std::size_t bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (std::size_t i = 0; i < bytes; ++i) {
      auto value = static_cast<unsigned int>(rng_() & 0xFF);
      out.push_back(kHex[(value >> 4) & 0xF]);
      out.push_back(kHex[value & 0xF]);
    }
    return out;
  }

  std::mutex mu_;
  std::unordered_map<std::string, DomainAuthToken> tokens_;
  std::mt19937_64 rng_{std::random_device{}()};
};

struct Runtime {
  config::AppConfig config;
  ProxyAuthStore proxy_auth;
  PortalSessionStore portal_sessions;
  PortalClientAuthStore portal_client_auth;
  ProxyDomainTokenStore domain_tokens;
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
                                    config.url_category_whitelist,
                                    config.url_category_blacklist,
                                    config.access_rules,
                                    policy::access_action_from_string(config.default_access_action)}),
        audit(config.audit_log_path, config.audit_recent_limit) {}

  bool portal_auth_enabled() const { return config.enable_proxy_auth && config.proxy_auth_mode != "basic"; }
  bool proxy_basic_enabled() const { return config.enable_proxy_auth && config.proxy_auth_mode != "portal"; }

  std::string build_proxy_auth_cookie_value(const std::string& username, const std::string& host) const {
    if (username.empty() || host.empty()) return "";
    const auto expires_at = std::chrono::system_clock::now() + std::chrono::seconds(config.proxy_auth_portal_session_ttl_sec);
    const auto exp_seconds = std::chrono::duration_cast<std::chrono::seconds>(expires_at.time_since_epoch()).count();
    const auto host_l = core::to_lower(host);
    const auto payload = username + "|" + host_l + "|" + std::to_string(exp_seconds);
    std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
    const auto body = core::sha256_hex(bytes);
    const auto sig_payload = config.proxy_auth_signing_key + "|" + body;
    std::vector<std::uint8_t> sig_bytes(sig_payload.begin(), sig_payload.end());
    const auto sig = core::sha256_hex(sig_bytes);
    return username + "|" + std::to_string(exp_seconds) + "|" + sig;
  }

  std::string validate_proxy_auth_cookie(const std::string& cookie_value, const std::string& host) const {
    auto parts = core::split(cookie_value, '|');
    if (parts.size() != 3) return "";
    const auto username = core::trim(parts[0]);
    const auto host_l = core::to_lower(host);
    if (username.empty() || host_l.empty()) return "";
    std::uint64_t exp_seconds = 0;
    try {
      exp_seconds = static_cast<std::uint64_t>(std::stoull(parts[1]));
    } catch (...) {
      return "";
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    if (exp_seconds <= now) return "";
    const auto payload = username + "|" + host_l + "|" + parts[1];
    std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
    const auto body = core::sha256_hex(bytes);
    const auto sig_payload = config.proxy_auth_signing_key + "|" + body;
    std::vector<std::uint8_t> sig_bytes(sig_payload.begin(), sig_payload.end());
    const auto expected_sig = core::sha256_hex(sig_bytes);
    return expected_sig == parts[2] ? username : "";
  }
};

inline std::string client_ip_from_addr(const std::string& client_addr) {
  auto pos = client_addr.rfind(':');
  if (pos == std::string::npos) return client_addr;
  return client_addr.substr(0, pos);
}

}  // namespace openscanproxy::proxy
