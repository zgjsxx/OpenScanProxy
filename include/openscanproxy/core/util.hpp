#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openscanproxy::core {

std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
std::string to_lower(std::string s);
std::string sha256_hex(const std::vector<uint8_t>& bytes);
std::string now_iso8601();
std::string json_escape(const std::string& in);

std::map<std::string, std::string> parse_simple_json_object(const std::string& text);

}  // namespace openscanproxy::core
