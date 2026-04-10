#pragma once

#include "openscanproxy/audit/audit.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/extractor/extractor.hpp"
#include "openscanproxy/policy/policy.hpp"
#include "openscanproxy/scanner/scanner.hpp"
#include "openscanproxy/stats/stats.hpp"
#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include <memory>

namespace openscanproxy::proxy {

struct Runtime {
  config::AppConfig config;
  std::unique_ptr<scanner::IScanner> scanner;
  scanner::ScanContext scan_ctx;
  policy::PolicyEngine policy;
  extractor::FileExtractor extractor;
  audit::AuditLogger audit;
  stats::StatsRegistry stats;
  tlsmitm::TLSMitmEngine tls_mitm;

  explicit Runtime(config::AppConfig cfg)
      : config(std::move(cfg)),
        policy(policy::PolicyConfig{config.policy_mode != "fail-close", config.suspicious_action == "block"}),
        audit(config.audit_log_path, config.audit_recent_limit) {}
};

}  // namespace openscanproxy::proxy
