#include "openscanproxy/http/http_message.hpp"

#include "openscanproxy/core/util.hpp"

#include <sstream>

namespace openscanproxy::http {

std::string header_get(const std::map<std::string, std::string>& headers, const std::string& key) {
  auto lk = core::to_lower(key);
  for (const auto& [k, v] : headers) {
    if (core::to_lower(k) == lk) return v;
  }
  return "";
}

static bool parse_headers(std::istream& is, std::map<std::string, std::string>& headers) {
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) return true;
    auto pos = line.find(':');
    if (pos == std::string::npos) return false;
    headers[core::trim(line.substr(0, pos))] = core::trim(line.substr(pos + 1));
  }
  return false;
}

bool parse_request(const std::string& raw, HttpRequest& req) {
  std::istringstream is(raw);
  std::string line;
  if (!std::getline(is, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream fl(line);
  if (!(fl >> req.method >> req.uri >> req.version)) return false;
  if (!parse_headers(is, req.headers)) return false;
  req.body.assign(std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>());
  return true;
}

bool parse_response(const std::string& raw, HttpResponse& resp) {
  std::istringstream is(raw);
  std::string line;
  if (!std::getline(is, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream fl(line);
  if (!(fl >> resp.version >> resp.status)) return false;
  std::getline(fl, resp.reason);
  resp.reason = core::trim(resp.reason);
  if (!parse_headers(is, resp.headers)) return false;
  resp.body.assign(std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>());
  return true;
}

std::string serialize_request(const HttpRequest& req) {
  std::ostringstream os;
  os << req.method << ' ' << req.uri << ' ' << req.version << "\r\n";
  for (const auto& [k, v] : req.headers) os << k << ": " << v << "\r\n";
  os << "\r\n";
  os.write(reinterpret_cast<const char*>(req.body.data()), static_cast<std::streamsize>(req.body.size()));
  return os.str();
}

std::string serialize_response(const HttpResponse& resp) {
  std::ostringstream os;
  os << resp.version << ' ' << resp.status << ' ' << resp.reason << "\r\n";
  for (const auto& [k, v] : resp.headers) os << k << ": " << v << "\r\n";
  os << "\r\n";
  os.write(reinterpret_cast<const char*>(resp.body.data()), static_cast<std::streamsize>(resp.body.size()));
  return os.str();
}

}  // namespace openscanproxy::http
