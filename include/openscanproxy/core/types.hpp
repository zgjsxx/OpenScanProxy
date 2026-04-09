#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openscanproxy::core {

enum class Direction { Upload, Download };

enum class ScanStatus { Clean, Infected, Suspicious, Error };

enum class Action { Allow, Block, LogOnly };

struct ExtractedFile {
  std::string filename;
  std::string mime;
  std::vector<uint8_t> bytes;
  Direction direction{Direction::Upload};
  std::string source_url;
  std::string source_host;
  std::map<std::string, std::string> metadata;
};

struct ScanResult {
  ScanStatus status{ScanStatus::Error};
  std::string scanner_name;
  std::string signature;
  std::uint64_t elapsed_ms{0};
  std::map<std::string, std::string> metadata;
  std::string error;
};

}  // namespace openscanproxy::core
