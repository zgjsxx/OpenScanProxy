#include "openscanproxy/policy/policy.hpp"

namespace openscanproxy::policy {

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

}  // namespace openscanproxy::policy
