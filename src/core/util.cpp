#include "openscanproxy/core/util.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/sha.h>
#include <regex>
#include <sstream>

namespace openscanproxy::core {

std::string trim(const std::string& s) {
  const auto b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  const auto e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= s.size()) {
    const auto pos = s.find(delim, start);
    if (pos == std::string::npos) {
      out.push_back(s.substr(start));
      break;
    }
    out.push_back(s.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

std::string sha256_hex(const std::vector<uint8_t>& bytes) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(bytes.data(), bytes.size(), hash);
  std::ostringstream oss;
  for (unsigned char c : hash) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  return oss.str();
}

std::string now_iso8601() {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string json_escape(const std::string& in) {
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

std::map<std::string, std::string> parse_simple_json_object(const std::string& text) {
  // 最小化解析器，用于扁平 key->(string|number|bool) JSON 对象。TODO: 如结构变复杂，替换为健壮的解析器。
  std::map<std::string, std::string> out;
  std::regex kv_regex("\\\"([^\\\"]+)\\\"\\s*:\\s*(\\\"([^\\\"]*)\\\"|true|false|-?[0-9]+)");
  for (std::sregex_iterator it(text.begin(), text.end(), kv_regex), end; it != end; ++it) {
    auto key = (*it)[1].str();
    auto raw = (*it)[2].str();
    if (!raw.empty() && raw.front() == '"' && raw.back() == '"') raw = raw.substr(1, raw.size() - 2);
    out[key] = raw;
  }
  return out;
}

}  // namespace openscanproxy::core


