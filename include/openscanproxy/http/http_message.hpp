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

}  // namespace openscanproxy::http
