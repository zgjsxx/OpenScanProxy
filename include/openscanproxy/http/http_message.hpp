#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openscanproxy::http {

struct HttpRequest {
  std::string method;
  std::string uri;
  std::string version{"HTTP/1.1"};
  std::map<std::string, std::string> headers;
  std::vector<uint8_t> body;
};

struct HttpResponse {
  std::string version{"HTTP/1.1"};
  int status{200};
  std::string reason{"OK"};
  std::map<std::string, std::string> headers;
  std::vector<uint8_t> body;
};

std::string header_get(const std::map<std::string, std::string>& headers, const std::string& key);
std::string serialize_request(const HttpRequest& req);
std::string serialize_response(const HttpResponse& resp);
bool parse_request(const std::string& raw, HttpRequest& req);
bool parse_response(const std::string& raw, HttpResponse& resp);
bool parse_request(const std::string& raw, HttpRequest& req, std::size_t* consumed);
bool parse_response(const std::string& raw, HttpResponse& resp, std::size_t* consumed);
bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded);
std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, std::size_t chunk_size = 4096);
bool message_should_close(const std::string& version, const std::map<std::string, std::string>& headers);

}  // namespace openscanproxy::http
