#include "openscanproxy/http/http_message.hpp"

#include "openscanproxy/core/util.hpp"

#include <charconv>
#include <sstream>

namespace openscanproxy::http {
namespace {

bool parse_headers_block(const std::string& block, std::map<std::string, std::string>& headers) {
  std::istringstream is(block);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    auto pos = line.find(':');
    if (pos == std::string::npos) return false;
    headers[core::trim(line.substr(0, pos))] = core::trim(line.substr(pos + 1));
  }
  return true;
}

bool parse_content_length(const std::map<std::string, std::string>& headers, std::size_t& out) {
  auto raw = header_get(headers, "Content-Length");
  if (raw.empty()) {
    out = 0;
    return true;
  }
  std::uint64_t v = 0;
  auto first = raw.data();
  auto last = raw.data() + raw.size();
  auto [ptr, ec] = std::from_chars(first, last, v);
  if (ec != std::errc() || ptr != last) return false;
  out = static_cast<std::size_t>(v);
  return true;
}

bool is_chunked(const std::map<std::string, std::string>& headers) {
  auto te = core::to_lower(header_get(headers, "Transfer-Encoding"));
  return te.find("chunked") != std::string::npos;
}

bool parse_message_body(const std::string& raw, std::size_t body_start, const std::map<std::string, std::string>& headers,
                        std::vector<std::uint8_t>& body, std::size_t* consumed) {
  body.clear();
  if (is_chunked(headers)) {
    std::vector<std::uint8_t> encoded(raw.begin() + static_cast<std::ptrdiff_t>(body_start), raw.end());
    if (!decode_chunked_body(encoded, body)) return false;
    if (consumed) *consumed = raw.size();
    return true;
  }

  std::size_t content_length = 0;
  if (!parse_content_length(headers, content_length)) return false;
  if (raw.size() < body_start + content_length) return false;

  body.assign(raw.begin() + static_cast<std::ptrdiff_t>(body_start),
              raw.begin() + static_cast<std::ptrdiff_t>(body_start + content_length));
  if (consumed) *consumed = body_start + content_length;
  return true;
}

}  // namespace

std::string header_get(const std::map<std::string, std::string>& headers, const std::string& key) {
  auto lk = core::to_lower(key);
  for (const auto& [k, v] : headers) {
    if (core::to_lower(k) == lk) return v;
  }
  return "";
}

bool parse_request(const std::string& raw, HttpRequest& req) { return parse_request(raw, req, nullptr); }

bool parse_request(const std::string& raw, HttpRequest& req, std::size_t* consumed) {
  req = HttpRequest{};
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos) return false;

  auto first_line_end = raw.find("\r\n");
  if (first_line_end == std::string::npos || first_line_end > header_end) return false;

  {
    std::istringstream fl(raw.substr(0, first_line_end));
    if (!(fl >> req.method >> req.uri >> req.version)) return false;
  }

  auto headers_block = raw.substr(first_line_end + 2, header_end - (first_line_end + 2));
  if (!parse_headers_block(headers_block, req.headers)) return false;

  return parse_message_body(raw, header_end + 4, req.headers, req.body, consumed);
}

bool parse_response(const std::string& raw, HttpResponse& resp) { return parse_response(raw, resp, nullptr); }

bool parse_response(const std::string& raw, HttpResponse& resp, std::size_t* consumed) {
  resp = HttpResponse{};
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos) return false;

  auto first_line_end = raw.find("\r\n");
  if (first_line_end == std::string::npos || first_line_end > header_end) return false;

  {
    std::istringstream fl(raw.substr(0, first_line_end));
    if (!(fl >> resp.version >> resp.status)) return false;
    std::getline(fl, resp.reason);
    resp.reason = core::trim(resp.reason);
  }

  auto headers_block = raw.substr(first_line_end + 2, header_end - (first_line_end + 2));
  if (!parse_headers_block(headers_block, resp.headers)) return false;

  return parse_message_body(raw, header_end + 4, resp.headers, resp.body, consumed);
}

bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded) {
  decoded.clear();
  std::size_t pos = 0;
  while (pos < encoded.size()) {
    auto line_end = std::string::npos;
    for (std::size_t i = pos; i + 1 < encoded.size(); ++i) {
      if (encoded[i] == '\r' && encoded[i + 1] == '\n') {
        line_end = i;
        break;
      }
    }
    if (line_end == std::string::npos) return false;

    std::string size_line(encoded.begin() + static_cast<std::ptrdiff_t>(pos),
                          encoded.begin() + static_cast<std::ptrdiff_t>(line_end));
    auto semicolon = size_line.find(';');
    if (semicolon != std::string::npos) size_line = size_line.substr(0, semicolon);
    size_line = core::trim(size_line);
    if (size_line.empty()) return false;

    std::size_t chunk_size = 0;
    try {
      chunk_size = static_cast<std::size_t>(std::stoull(size_line, nullptr, 16));
    } catch (...) {
      return false;
    }

    pos = line_end + 2;
    if (chunk_size == 0) {
      if (pos + 2 > encoded.size()) return false;
      return encoded[pos] == '\r' && encoded[pos + 1] == '\n';
    }

    if (pos + chunk_size + 2 > encoded.size()) return false;
    decoded.insert(decoded.end(), encoded.begin() + static_cast<std::ptrdiff_t>(pos),
                   encoded.begin() + static_cast<std::ptrdiff_t>(pos + chunk_size));
    pos += chunk_size;
    if (encoded[pos] != '\r' || encoded[pos + 1] != '\n') return false;
    pos += 2;
  }
  return false;
}

std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, std::size_t chunk_size) {
  if (chunk_size == 0) chunk_size = 4096;
  std::vector<uint8_t> out;

  std::size_t pos = 0;
  while (pos < body.size()) {
    auto n = std::min(chunk_size, body.size() - pos);
    std::ostringstream line;
    line << std::hex << n << "\r\n";
    auto header = line.str();
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), body.begin() + static_cast<std::ptrdiff_t>(pos),
               body.begin() + static_cast<std::ptrdiff_t>(pos + n));
    out.push_back('\r');
    out.push_back('\n');
    pos += n;
  }
  static constexpr char tail[] = "0\r\n\r\n";
  out.insert(out.end(), tail, tail + sizeof(tail) - 1);
  return out;
}

std::string serialize_request(const HttpRequest& req) {
  std::ostringstream os;
  os << req.method << ' ' << req.uri << ' ' << req.version << "\r\n";
  for (const auto& [k, v] : req.headers) os << k << ": " << v << "\r\n";
  os << "\r\n";
  if (is_chunked(req.headers)) {
    auto encoded = encode_chunked_body(req.body);
    os.write(reinterpret_cast<const char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
  } else {
    os.write(reinterpret_cast<const char*>(req.body.data()), static_cast<std::streamsize>(req.body.size()));
  }
  return os.str();
}

std::string serialize_response(const HttpResponse& resp) {
  std::ostringstream os;
  os << resp.version << ' ' << resp.status << ' ' << resp.reason << "\r\n";
  for (const auto& [k, v] : resp.headers) os << k << ": " << v << "\r\n";
  os << "\r\n";
  if (is_chunked(resp.headers)) {
    auto encoded = encode_chunked_body(resp.body);
    os.write(reinterpret_cast<const char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
  } else {
    os.write(reinterpret_cast<const char*>(resp.body.data()), static_cast<std::streamsize>(resp.body.size()));
  }
  return os.str();
}

bool message_should_close(const std::string& version, const std::map<std::string, std::string>& headers) {
  auto connection = core::to_lower(header_get(headers, "Connection"));
  if (connection.find("close") != std::string::npos) return true;
  if (version == "HTTP/1.0") return connection.find("keep-alive") == std::string::npos;
  return false;
}

}  // namespace openscanproxy::http
