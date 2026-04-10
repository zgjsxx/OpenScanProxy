#include "openscanproxy/policy/policy.hpp"

#include "openscanproxy/core/util.hpp"

namespace openscanproxy::policy {
namespace {

bool wildcard_match_impl(const std::string& value, const std::string& pattern, std::size_t vi, std::size_t pi) {
  if (pi == pattern.size()) return vi == value.size();
  if (pattern[pi] == '*') {
    for (std::size_t i = vi; i <= value.size(); ++i) {
      if (wildcard_match_impl(value, pattern, i, pi + 1)) return true;
    }
    return false;
  }
  if (vi < value.size() && value[vi] == pattern[pi]) return wildcard_match_impl(value, pattern, vi + 1, pi + 1);
  return false;
}

bool wildcard_match(const std::string& value, const std::string& pattern) {
  return wildcard_match_impl(value, pattern, 0, 0);
}

bool match_rule(const std::string& value, const std::string& rule) {
  if (rule.empty()) return false;
  if (value == rule) return true;
  if (rule.find('*') != std::string::npos) return wildcard_match(value, rule);
  if (rule.back() == '/') return value.rfind(rule, 0) == 0;
  return false;
}

bool find_matched_rule(const std::vector<std::string>& rules, const std::string& value, std::string& hit) {
  for (const auto& rule : rules) {
    if (match_rule(value, rule)) {
      hit = rule;
      return true;
    }
  }
  return false;
}

}  // namespace

core::Action PolicyEngine::decide(const core::ScanResult& result) const {
  auto cfg = config();
  switch (result.status) {
    case core::ScanStatus::Clean:
      return core::Action::Allow;
    case core::ScanStatus::Infected:
      return core::Action::Block;
    case core::ScanStatus::Suspicious:
      return cfg.block_suspicious ? core::Action::Block : core::Action::LogOnly;
    case core::ScanStatus::Error:
      return cfg.fail_open ? core::Action::Allow : core::Action::Block;
  }
  return core::Action::Block;
}

AccessPolicyResult PolicyEngine::evaluate_access(const std::string& host, const std::string& url,
                                                 const std::string& /*method*/) const {
  auto cfg = config();
  const auto host_l = core::to_lower(host);
  std::string hit;

  if (find_matched_rule(cfg.domain_whitelist, host_l, hit)) {
    return {AccessAction::Allow, hit, "domain_whitelist", "matched domain whitelist"};
  }
  if (find_matched_rule(cfg.url_whitelist, url, hit)) {
    return {AccessAction::Allow, hit, "url_whitelist", "matched url whitelist"};
  }
  if (find_matched_rule(cfg.domain_blacklist, host_l, hit)) {
    return {AccessAction::Block, hit, "domain_blacklist", "matched domain blacklist"};
  }
  if (find_matched_rule(cfg.url_blacklist, url, hit)) {
    return {AccessAction::Block, hit, "url_blacklist", "matched url blacklist"};
  }
  return {cfg.default_access_action, "", "default_access_action", "fallback to default access action"};
}

PolicyConfig PolicyEngine::config() const {
  std::lock_guard<std::mutex> lk(mu_);
  return cfg_;
}

void PolicyEngine::update(PolicyConfig cfg) {
  std::lock_guard<std::mutex> lk(mu_);
  cfg_ = cfg;
}

std::string to_string(core::ScanStatus status) {
  switch (status) {
    case core::ScanStatus::Clean: return "clean";
    case core::ScanStatus::Infected: return "infected";
    case core::ScanStatus::Suspicious: return "suspicious";
    case core::ScanStatus::Error: return "error";
  }
  return "error";
}

std::string to_string(core::Action action) {
  switch (action) {
    case core::Action::Allow: return "allow";
    case core::Action::Block: return "block";
    case core::Action::LogOnly: return "log";
  }
  return "block";
}

std::string to_string(AccessAction action) {
  switch (action) {
    case AccessAction::Allow: return "allow";
    case AccessAction::Block: return "block";
  }
  return "allow";
}

AccessAction access_action_from_string(const std::string& action) {
  return core::to_lower(action) == "block" ? AccessAction::Block : AccessAction::Allow;
}

}  // namespace openscanproxy::policy
