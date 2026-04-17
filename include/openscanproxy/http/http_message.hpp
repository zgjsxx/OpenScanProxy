#pragma once

#include <cstdint>
#include <utility>
#include <string>
#include <vector>

namespace openscanproxy::http {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct HttpRequest {
  std::string method;
  std::string uri;
  std::string version{"HTTP/1.1"};
  Headers headers;
  Headers trailers;  // chunked 编码的 trailer 头部
  std::vector<uint8_t> body;
};

struct HttpResponse {
  std::string version{"HTTP/1.1"};
  int status{200};
  std::string reason{"OK"};
  Headers headers;
  Headers trailers;  // chunked 编码的 trailer 头部
  std::vector<uint8_t> body;
};

std::string header_get(const Headers& headers, const std::string& key);
std::vector<std::string> header_get_all(const Headers& headers, const std::string& key);
void header_add(Headers& headers, std::string key, std::string value);
void header_set(Headers& headers, std::string key, std::string value);
void header_erase(Headers& headers, const std::string& key);
std::string serialize_request(const HttpRequest& req);
std::string serialize_response(const HttpResponse& resp);
bool parse_request(const std::string& raw, HttpRequest& req);
bool parse_response(const std::string& raw, HttpResponse& resp);
bool parse_request(const std::string& raw, HttpRequest& req, std::size_t* consumed);
bool parse_response(const std::string& raw, HttpResponse& resp, std::size_t* consumed);
bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded);
bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded, Headers& trailers);
std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, std::size_t chunk_size = 4096);
std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, const Headers& trailers, std::size_t chunk_size = 4096);
bool message_should_close(const std::string& version, const Headers& headers);

}  // namespace openscanproxy::http
