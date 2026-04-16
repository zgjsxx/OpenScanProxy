#include "openscanproxy/http/http_message.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using openscanproxy::http::HttpRequest;
using openscanproxy::http::HttpResponse;

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool test_request_without_body() {
  const std::string raw = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request without body") &&
         expect(req.body.empty(), "request body empty") && expect(consumed == raw.size(), "consumed full request");
}

bool test_request_fixed_content_length() {
  const std::string raw = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request fixed body") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello", "request body exact content-length") &&
         expect(consumed == raw.find("hello") + 5, "request consumed exact bytes");
}

bool test_response_chunked() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
  HttpResponse resp;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_response(raw, resp, &consumed), "parse response chunked") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "Wikipedia", "decode chunked body") &&
         expect(consumed == raw.size(), "chunked consumed full response");
}

bool test_chunked_encode_roundtrip() {
  std::vector<uint8_t> body{'a', 'b', 'c', 'd', 'e', 'f'};
  auto encoded = openscanproxy::http::encode_chunked_body(body, 2);
  std::vector<uint8_t> decoded;
  return expect(openscanproxy::http::decode_chunked_body(encoded, decoded), "decode encoded chunked") &&
         expect(decoded == body, "chunked roundtrip");
}

bool test_invalid_message() {
  const std::string raw = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc";
  HttpRequest req;
  return expect(!openscanproxy::http::parse_request(raw, req), "reject short content-length body");
}

bool test_duplicate_headers_preserved_in_response() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nWarning: 199 misc\r\nWarning: 299 misc2\r\n\r\n";
  HttpResponse resp;
  if (!expect(openscanproxy::http::parse_response(raw, resp), "parse response with duplicate headers")) return false;
  auto cookies = openscanproxy::http::header_get_all(resp.headers, "Set-Cookie");
  auto warnings = openscanproxy::http::header_get_all(resp.headers, "Warning");
  auto serialized = openscanproxy::http::serialize_response(resp);
  return expect(cookies.size() == 2, "preserve duplicate set-cookie count") &&
         expect(cookies[0] == "a=1" && cookies[1] == "b=2", "preserve duplicate set-cookie order") &&
         expect(warnings.size() == 2, "preserve duplicate warning count") &&
         expect(serialized.find("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n") != std::string::npos, "serialize duplicate set-cookie headers") &&
         expect(serialized.find("Warning: 199 misc\r\nWarning: 299 misc2\r\n") != std::string::npos, "serialize duplicate warning headers");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_request_without_body() && ok;
  ok = test_request_fixed_content_length() && ok;
  ok = test_response_chunked() && ok;
  ok = test_chunked_encode_roundtrip() && ok;
  ok = test_invalid_message() && ok;
  ok = test_duplicate_headers_preserved_in_response() && ok;
  if (ok) {
    std::cout << "All http_message tests passed\n";
    return 0;
  }
  return 1;
}
