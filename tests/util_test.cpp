#include "openscanproxy/core/util.hpp"

#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool test_trim_handles_whitespace_and_all_blank_input() {
  return expect(openscanproxy::core::trim("  abc\r\n") == "abc", "trim removes outer whitespace") &&
         expect(openscanproxy::core::trim("\t \r\n") == "", "trim returns empty for all whitespace");
}

bool test_split_preserves_empty_segments() {
  const auto parts = openscanproxy::core::split("a,,b,", ',');
  return expect(parts.size() == 4, "split keeps empty segments") &&
         expect(parts[0] == "a" && parts[1].empty() && parts[2] == "b" && parts[3].empty(),
                "split preserves exact segment order");
}

bool test_to_lower_converts_ascii_letters_only() {
  return expect(openscanproxy::core::to_lower("HeLLo-123") == "hello-123", "to_lower normalizes letters");
}

bool test_sha256_hex_matches_known_vector() {
  const std::vector<uint8_t> bytes{'a', 'b', 'c'};
  return expect(openscanproxy::core::sha256_hex(bytes) ==
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "sha256_hex matches known digest");
}

bool test_now_iso8601_uses_utc_timestamp_shape() {
  const auto value = openscanproxy::core::now_iso8601();
  const std::regex pattern(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$)");
  return expect(std::regex_match(value, pattern), "now_iso8601 returns RFC3339-like UTC shape");
}

bool test_json_escape_escapes_control_characters() {
  const auto escaped = openscanproxy::core::json_escape("a\"\\\n\r\tb");
  return expect(escaped == "a\\\"\\\\\\n\\r\\tb", "json_escape escapes quotes slash and controls");
}

bool test_parse_simple_json_object_reads_string_number_and_bool() {
  const auto parsed = openscanproxy::core::parse_simple_json_object(
      R"({"name":"proxy","port":8080,"enabled":true,"offset":-7})");
  return expect(parsed.size() == 4, "parse_simple_json_object reads four fields") &&
         expect(parsed.at("name") == "proxy", "parse string field") &&
         expect(parsed.at("port") == "8080", "parse numeric field") &&
         expect(parsed.at("enabled") == "true", "parse bool field") &&
         expect(parsed.at("offset") == "-7", "parse negative field");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_trim_handles_whitespace_and_all_blank_input() && ok;
  ok = test_split_preserves_empty_segments() && ok;
  ok = test_to_lower_converts_ascii_letters_only() && ok;
  ok = test_sha256_hex_matches_known_vector() && ok;
  ok = test_now_iso8601_uses_utc_timestamp_shape() && ok;
  ok = test_json_escape_escapes_control_characters() && ok;
  ok = test_parse_simple_json_object_reads_string_number_and_bool() && ok;
  if (ok) {
    std::cout << "All util tests passed\n";
    return 0;
  }
  return 1;
}
