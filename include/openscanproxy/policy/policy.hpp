#pragma once

#include "openscanproxy/core/types.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace openscanproxy::policy {

enum class AccessAction { Allow, Block };

struct PolicyConfig {
  bool fail_open{true};
  bool block_suspicious{false};
  std::vector<std::string> domain_whitelist;
  std::vector<std::string> domain_blacklist;
  std::vector<std::string> user_whitelist;
  std::vector<std::string> user_blacklist;
  std::vector<std::string> url_whitelist;
  std::vector<std::string> url_blacklist;
  AccessAction default_access_action{AccessAction::Allow};
};

struct AccessPolicyResult {
  AccessAction action{AccessAction::Allow};
  std::string matched_rule;
  std::string matched_type;
  std::string reason;
};

class PolicyEngine {
 public:
  explicit PolicyEngine(PolicyConfig cfg) : cfg_(cfg) {}
  core::Action decide(const core::ScanResult& result) const;
  AccessPolicyResult evaluate_access(const std::string& host, const std::string& url, const std::string& method,
                                     const std::string& user = "") const;
  PolicyConfig config() const;
  void update(PolicyConfig cfg);

 private:
  mutable std::mutex mu_;
  PolicyConfig cfg_;
};

std::string to_string(core::ScanStatus status);
std::string to_string(core::Action action);
std::string to_string(AccessAction action);
AccessAction access_action_from_string(const std::string& action);

}  // namespace openscanproxy::policy
