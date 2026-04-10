#pragma once

#include "openscanproxy/core/types.hpp"

#include <mutex>
#include <string>

namespace openscanproxy::policy {

struct PolicyConfig {
  bool fail_open{true};
  bool block_suspicious{false};
};

class PolicyEngine {
 public:
  explicit PolicyEngine(PolicyConfig cfg) : cfg_(cfg) {}
  core::Action decide(const core::ScanResult& result) const;
  PolicyConfig config() const;
  void update(PolicyConfig cfg);

 private:
  mutable std::mutex mu_;
  PolicyConfig cfg_;
};

std::string to_string(core::ScanStatus status);
std::string to_string(core::Action action);

}  // namespace openscanproxy::policy
