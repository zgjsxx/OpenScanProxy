#include "openscanproxy/http/http_message.hpp"

#include <iostream>
#include <string>

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool test_header_helpers_preserve_duplicates() {
  openscanproxy::http::Headers headers;
  openscanproxy::http::header_add(headers, "Set-Cookie", "a=1");
  openscanproxy::http::header_add(headers, "set-cookie", "b=2");
  openscanproxy::http::header_add(headers, "Via", "proxy-a");

  auto cookies = openscanproxy::http::header_get_all(headers, "Set-Cookie");
  return expect(cookies.size() == 2, "header_get_all preserves duplicates") &&
         expect(openscanproxy::http::header_get(headers, "SET-cookie") == "b=2", "header_get returns last matching value");
}

bool test_header_set_replaces_all_duplicates() {
  openscanproxy::http::Headers headers;
  openscanproxy::http::header_add(headers, "Warning", "199 old");
  openscanproxy::http::header_add(headers, "Warning", "299 old2");
  openscanproxy::http::header_set(headers, "Warning", "399 new");
  auto warnings = openscanproxy::http::header_get_all(headers, "warning");
  return expect(warnings.size() == 1, "header_set replaces all duplicates") &&
         expect(warnings[0] == "399 new", "header_set stores replacement value");
}

bool test_header_erase_removes_all_duplicates() {
  openscanproxy::http::Headers headers;
  openscanproxy::http::header_add(headers, "Set-Cookie", "a=1");
  openscanproxy::http::header_add(headers, "Set-Cookie", "b=2");
  openscanproxy::http::header_erase(headers, "set-cookie");
  return expect(openscanproxy::http::header_get_all(headers, "Set-Cookie").empty(), "header_erase removes all duplicates");
}

bool test_message_should_close_semantics() {
  openscanproxy::http::Headers h11;
  openscanproxy::http::header_add(h11, "Connection", "keep-alive");
  openscanproxy::http::Headers h10;
  openscanproxy::http::header_add(h10, "Connection", "keep-alive");
  openscanproxy::http::Headers close_headers;
  openscanproxy::http::header_add(close_headers, "Connection", "close");

  return expect(!openscanproxy::http::message_should_close("HTTP/1.1", h11), "http/1.1 keep alive by default") &&
         expect(!openscanproxy::http::message_should_close("HTTP/1.0", h10), "http/1.0 keep-alive honored") &&
         expect(openscanproxy::http::message_should_close("HTTP/1.1", close_headers), "connection close honored");
}

bool test_chunked_request_with_extensions() {
  const std::string raw =
      "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
      "5;foo=bar\r\nhello\r\n0\r\n\r\n";
  openscanproxy::http::HttpRequest req;
  return expect(openscanproxy::http::parse_request(raw, req), "parse chunked request with extension") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello", "decode chunked request body");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_header_helpers_preserve_duplicates() && ok;
  ok = test_header_set_replaces_all_duplicates() && ok;
  ok = test_header_erase_removes_all_duplicates() && ok;
  ok = test_message_should_close_semantics() && ok;
  ok = test_chunked_request_with_extensions() && ok;
  if (ok) {
    std::cout << "All http_protocol tests passed\n";
    return 0;
  }
  return 1;
}
