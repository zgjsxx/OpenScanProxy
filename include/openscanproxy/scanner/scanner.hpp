#pragma once

#include "openscanproxy/core/types.hpp"

#include <memory>

namespace openscanproxy::scanner {

struct ScanContext {
  std::uint64_t timeout_ms{5000};
};

class IScanner {
 public:
  virtual ~IScanner() = default;
  virtual const char* name() const = 0;
  virtual core::ScanResult scan(const core::ExtractedFile& file, const ScanContext& ctx) = 0;
};

std::unique_ptr<IScanner> create_mock_scanner();
std::unique_ptr<IScanner> create_clamav_scanner(const std::string& mode, const std::string& unix_socket,
                                                const std::string& host, uint16_t port);

}  // namespace openscanproxy::scanner
