#include "openscanproxy/scanner/scanner.hpp"

#include "openscanproxy/core/util.hpp"

#include <chrono>

namespace openscanproxy::scanner {

class MockScanner final : public IScanner {
 public:
  const char* name() const override { return "MockScanner"; }

  core::ScanResult scan(const core::ExtractedFile& file, const ScanContext&) override {
    auto begin = std::chrono::steady_clock::now();
    core::ScanResult r;
    r.scanner_name = name();
    const std::string fname = core::to_lower(file.filename);
    std::string content(file.bytes.begin(), file.bytes.end());
    std::string lowered = core::to_lower(content);
    if (fname.find("eicar") != std::string::npos || lowered.find("virus") != std::string::npos) {
      r.status = core::ScanStatus::Infected;
      r.signature = "Mock.Eicar.Test";
    } else if (fname.find("susp") != std::string::npos) {
      r.status = core::ScanStatus::Suspicious;
      r.signature = "Mock.Suspicious.Pattern";
    } else {
      r.status = core::ScanStatus::Clean;
    }
    r.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    return r;
  }
};

std::unique_ptr<IScanner> create_mock_scanner() { return std::make_unique<MockScanner>(); }

}  // namespace openscanproxy::scanner
