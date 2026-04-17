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

// Verifies the simplest request parse path: headers end with CRLFCRLF, there is
// no payload, and the parser should consume the whole buffer without inventing
// a body. This protects the common GET/HEAD style request path.
bool test_request_without_body() {
  const std::string raw = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request without body") &&
         expect(req.body.empty(), "request body empty") && expect(consumed == raw.size(), "consumed full request");
}

// Verifies Content-Length framing for requests. The parser must read exactly
// the declared body bytes, stop before trailing data, and report the consumed
// length precisely so upper layers can continue parsing pipelined buffers.
bool test_request_fixed_content_length() {
  const std::string raw = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request fixed body") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello", "request body exact content-length") &&
         expect(consumed == raw.find("hello") + 5, "request consumed exact bytes");
}

// Verifies Transfer-Encoding: chunked takes precedence over Content-Length.
// This is a core request-smuggling hardening rule: once chunked framing is
// present and valid, the parser must ignore Content-Length and decode only the
// chunked body.
bool test_request_chunked_overrides_content_length() {
  const std::string raw =
      "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
      "5\r\nhello\r\n0\r\n\r\n";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request with chunked and content-length") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello", "chunked body wins over content-length") &&
         expect(consumed == raw.size(), "chunked framing consumes full request");
}

// Verifies chunked transfer decoding on responses. This is critical for proxy
// forwarding because many upstream servers stream bodies with chunked framing,
// and we must reassemble the payload correctly before policy/scanning logic.
bool test_response_chunked() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
  HttpResponse resp;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_response(raw, resp, &consumed), "parse response chunked") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "Wikipedia", "decode chunked body") &&
         expect(consumed == raw.size(), "chunked consumed full response");
}

// Verifies our chunked encoder and decoder interoperate. This gives a compact
// roundtrip check that the generated wire format can be parsed back into the
// original binary payload without corruption.
bool test_chunked_encode_roundtrip() {
  std::vector<uint8_t> body{'a', 'b', 'c', 'd', 'e', 'f'};
  auto encoded = openscanproxy::http::encode_chunked_body(body, 2);
  std::vector<uint8_t> decoded;
  return expect(openscanproxy::http::decode_chunked_body(encoded, decoded), "decode encoded chunked") &&
         expect(decoded == body, "chunked roundtrip");
}

// Verifies malformed framing is rejected instead of partially accepted. Here
// Content-Length says 10 bytes while only 3 are present, so the parser must
// fail rather than hand incomplete data to the rest of the proxy stack.
bool test_invalid_message() {
  const std::string raw = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc";
  HttpRequest req;
  return expect(!openscanproxy::http::parse_request(raw, req), "reject short content-length body");
}

// Verifies conflicting Content-Length values are rejected. Accepting ambiguous
// lengths is dangerous in a proxy because different peers may pick different
// body boundaries and enable request smuggling.
bool test_reject_conflicting_content_length_values() {
  const std::string raw =
      "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello!!";
  HttpRequest req;
  return expect(!openscanproxy::http::parse_request(raw, req), "reject conflicting content-length values");
}

// Verifies unsupported Transfer-Encoding chains are rejected. The current HTTP
// layer only supports plain bodies and a final chunked coding, so anything
// else must fail closed instead of being parsed ambiguously.
bool test_reject_invalid_transfer_encoding_chain() {
  const std::string raw =
      "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"
      "5\r\nhello\r\n0\r\n\r\n";
  HttpRequest req;
  return expect(!openscanproxy::http::parse_request(raw, req), "reject invalid transfer-encoding chain");
}

// Verifies duplicate response headers are preserved verbatim for headers whose
// semantics depend on repetition, such as Set-Cookie and Warning. This guards
// against the classic proxy bug where duplicate fields are collapsed and the
// downstream browser loses cookies or advisory metadata.
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

// 验证含 trailer 的 chunked 响应可以被正确解析，trailer 头部被保存在 resp.trailers 中。
bool test_response_chunked_with_trailers() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
      "4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Digest: sha256=abc\r\n\r\n";
  HttpResponse resp;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_response(raw, resp, &consumed), "parse response chunked with trailers") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "Wikipedia", "chunked body with trailers") &&
         expect(resp.trailers.size() == 1, "one trailer header") &&
         expect(resp.trailers[0].first == "X-Digest" && resp.trailers[0].second == "sha256=abc", "trailer content") &&
         expect(consumed == raw.size(), "chunked with trailers consumed full response");
}

// 验证含多个 trailer 的 chunked 响应解析。
bool test_response_chunked_with_multiple_trailers() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
      "5\r\nhello\r\n0\r\nX-Digest: abc\r\nX-Status: ok\r\n\r\n";
  HttpResponse resp;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_response(raw, resp, &consumed), "parse response with multiple trailers") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "hello", "body with multiple trailers") &&
         expect(resp.trailers.size() == 2, "two trailer headers") &&
         expect(resp.trailers[0].first == "X-Digest" && resp.trailers[1].first == "X-Status", "trailer names");
}

// 验证含 trailer 的 chunked 请求可以被正确解析。
bool test_request_chunked_with_trailers() {
  const std::string raw =
      "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
      "5\r\nhello\r\n0\r\nX-Checksum: md5=xyz\r\n\r\n";
  HttpRequest req;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_request(raw, req, &consumed), "parse request chunked with trailers") &&
         expect(std::string(req.body.begin(), req.body.end()) == "hello", "request body with trailers") &&
         expect(req.trailers.size() == 1, "request trailer count") &&
         expect(req.trailers[0].first == "X-Checksum" && req.trailers[0].second == "md5=xyz", "request trailer content") &&
         expect(consumed == raw.size(), "request chunked with trailers consumed");
}

// 验证含 trailer 的 chunked 编解码 roundtrip：编码后可解码回原始 body 和 trailers。
bool test_chunked_encode_roundtrip_with_trailers() {
  std::vector<uint8_t> body{'a', 'b', 'c', 'd', 'e', 'f'};
  openscanproxy::http::Headers trailers;
  trailers.emplace_back("X-Digest", "sha256=abc");
  trailers.emplace_back("X-Status", "ok");
  auto encoded = openscanproxy::http::encode_chunked_body(body, trailers, 2);
  std::vector<uint8_t> decoded;
  openscanproxy::http::Headers decoded_trailers;
  return expect(openscanproxy::http::decode_chunked_body(encoded, decoded, decoded_trailers), "decode with trailers roundtrip") &&
         expect(decoded == body, "roundtrip body matches") &&
         expect(decoded_trailers.size() == 2, "roundtrip trailer count") &&
         expect(decoded_trailers[0].first == "X-Digest" && decoded_trailers[0].second == "sha256=abc", "roundtrip trailer 1") &&
         expect(decoded_trailers[1].first == "X-Status" && decoded_trailers[1].second == "ok", "roundtrip trailer 2");
}

// 验证序列化时 RFC 7230 禁止出现在 trailer 的头部（Transfer-Encoding、Content-Length 等）被跳过。
bool test_disallowed_trailer_fields_stripped() {
  std::vector<uint8_t> body{'h', 'e', 'l', 'l', 'o'};
  openscanproxy::http::Headers trailers;
  trailers.emplace_back("X-Valid", "yes");
  trailers.emplace_back("Content-Length", "5");
  trailers.emplace_back("Transfer-Encoding", "chunked");
  trailers.emplace_back("Connection", "keep-alive");
  trailers.emplace_back("X-Also-Valid", "ok");
  auto encoded = openscanproxy::http::encode_chunked_body(body, trailers, 3);
  std::vector<uint8_t> decoded;
  openscanproxy::http::Headers decoded_trailers;
  return expect(openscanproxy::http::decode_chunked_body(encoded, decoded, decoded_trailers), "decode disallowed stripped") &&
         expect(decoded == body, "disallowed stripped body") &&
         expect(decoded_trailers.size() == 2, "only allowed trailers remain") &&
         expect(decoded_trailers[0].first == "X-Valid", "first allowed trailer") &&
         expect(decoded_trailers[1].first == "X-Also-Valid", "second allowed trailer");
}

// 回归测试：无 trailer 的 chunked 消息行为与修改前完全一致。
bool test_empty_trailers_no_change() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
  HttpResponse resp;
  std::size_t consumed = 0;
  return expect(openscanproxy::http::parse_response(raw, resp, &consumed), "parse response no trailers regression") &&
         expect(std::string(resp.body.begin(), resp.body.end()) == "Wikipedia", "no trailers body regression") &&
         expect(resp.trailers.empty(), "no trailers regression") &&
         expect(consumed == raw.size(), "no trailers consumed regression");
}

// 验证无冒号的 trailer 行被拒绝（格式错误）。
bool test_invalid_trailer_no_colon() {
  const std::string raw =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\ninvalidline\r\n\r\n";
  HttpResponse resp;
  return expect(!openscanproxy::http::parse_response(raw, resp), "reject trailer without colon");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_request_without_body() && ok;
  ok = test_request_fixed_content_length() && ok;
  ok = test_request_chunked_overrides_content_length() && ok;
  ok = test_response_chunked() && ok;
  ok = test_chunked_encode_roundtrip() && ok;
  ok = test_invalid_message() && ok;
  ok = test_reject_conflicting_content_length_values() && ok;
  ok = test_reject_invalid_transfer_encoding_chain() && ok;
  ok = test_duplicate_headers_preserved_in_response() && ok;
  ok = test_response_chunked_with_trailers() && ok;
  ok = test_response_chunked_with_multiple_trailers() && ok;
  ok = test_request_chunked_with_trailers() && ok;
  ok = test_chunked_encode_roundtrip_with_trailers() && ok;
  ok = test_disallowed_trailer_fields_stripped() && ok;
  ok = test_empty_trailers_no_change() && ok;
  ok = test_invalid_trailer_no_colon() && ok;
  if (ok) {
    std::cout << "All http_message tests passed\n";
    return 0;
  }
  return 1;
}
