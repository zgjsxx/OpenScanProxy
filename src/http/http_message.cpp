#include "openscanproxy/http/http_message.hpp"

#include "openscanproxy/core/util.hpp"

#include <algorithm>
#include <charconv>
#include <sstream>

namespace openscanproxy::http {
namespace {

bool header_name_equals(const std::string& lhs, const std::string& rhs) {
  return core::to_lower(lhs) == core::to_lower(rhs);
}

bool parse_headers_block(const std::string& block, Headers& headers) {
  std::istringstream is(block);
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    auto pos = line.find(':');
    if (pos == std::string::npos) return false;
    headers.emplace_back(core::trim(line.substr(0, pos)), core::trim(line.substr(pos + 1)));
  }
  return true;
}

std::vector<std::string> split_header_tokens(const std::string& value) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= value.size()) {
    auto comma = value.find(',', start);
    auto token = core::trim(value.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
    if (!token.empty()) out.push_back(token);
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return out;
}

bool parse_content_length(const Headers& headers, std::size_t& out) {
  auto values = header_get_all(headers, "Content-Length");
  if (values.empty()) {
    out = 0;
    return true;
  }

  bool have_value = false;
  std::uint64_t parsed_value = 0;
  for (const auto& raw_value : values) {
    auto tokens = split_header_tokens(raw_value);
    if (tokens.empty()) return false;
    for (const auto& token : tokens) {
      std::uint64_t v = 0;
      auto first = token.data();
      auto last = token.data() + token.size();
      auto [ptr, ec] = std::from_chars(first, last, v);
      if (ec != std::errc() || ptr != last) return false;
      if (have_value && parsed_value != v) return false;
      parsed_value = v;
      have_value = true;
    }
  }

  if (!have_value) return false;
  out = static_cast<std::size_t>(parsed_value);
  return true;
}

enum class TransferEncodingMode {
  None,
  Chunked,
};

bool parse_transfer_encoding_mode(const Headers& headers, TransferEncodingMode& mode) {
  auto values = header_get_all(headers, "Transfer-Encoding");
  if (values.empty()) {
    mode = TransferEncodingMode::None;
    return true;
  }

  std::vector<std::string> codings;
  for (const auto& value : values) {
    auto tokens = split_header_tokens(core::to_lower(value));
    if (tokens.empty()) return false;
    codings.insert(codings.end(), tokens.begin(), tokens.end());
  }

  bool saw_chunked = false;
  for (std::size_t i = 0; i < codings.size(); ++i) {
    const auto& coding = codings[i];
    if (coding == "chunked") {
      if (saw_chunked || i + 1 != codings.size()) return false;
      saw_chunked = true;
      continue;
    }

    // 当前解析器仅支持固定长度正文和最终分块传输编码。
    // 其他传输编码必须被拒绝，而非做模糊解读。
    return false;
  }

  mode = saw_chunked ? TransferEncodingMode::Chunked : TransferEncodingMode::None;
  return true;
}

bool parse_message_body(const std::string& raw, std::size_t body_start, const Headers& headers,
                        std::vector<std::uint8_t>& body, Headers& trailers, std::size_t* consumed) {
  body.clear();
  trailers.clear();
  TransferEncodingMode transfer_encoding_mode = TransferEncodingMode::None;
  if (!parse_transfer_encoding_mode(headers, transfer_encoding_mode)) return false;

  if (transfer_encoding_mode == TransferEncodingMode::Chunked) {
    std::vector<std::uint8_t> encoded(raw.begin() + static_cast<std::ptrdiff_t>(body_start), raw.end());
    if (!decode_chunked_body(encoded, body, trailers)) return false;
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

std::string header_get(const Headers& headers, const std::string& key) {
  auto values = header_get_all(headers, key);
  return values.empty() ? "" : values.back();
}

std::vector<std::string> header_get_all(const Headers& headers, const std::string& key) {
  std::vector<std::string> out;
  for (const auto& [k, v] : headers) {
    if (header_name_equals(k, key)) out.push_back(v);
  }
  return out;
}

void header_add(Headers& headers, std::string key, std::string value) {
  headers.emplace_back(std::move(key), std::move(value));
}

void header_set(Headers& headers, std::string key, std::string value) {
  header_erase(headers, key);
  header_add(headers, std::move(key), std::move(value));
}

void header_erase(Headers& headers, const std::string& key) {
  headers.erase(std::remove_if(headers.begin(), headers.end(), [&](const auto& item) {
    return header_name_equals(item.first, key);
  }), headers.end());
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

  return parse_message_body(raw, header_end + 4, req.headers, req.body, req.trailers, consumed);
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

  return parse_message_body(raw, header_end + 4, resp.headers, resp.body, resp.trailers, consumed);
}

bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded, Headers& trailers) {
  decoded.clear();
  trailers.clear();
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
      // 读取 trailer 头部，直到遇到空行（仅 \r\n）
      while (pos + 1 < encoded.size()) {
        auto trailer_line_end = std::string::npos;
        for (std::size_t i = pos; i + 1 < encoded.size(); ++i) {
          if (encoded[i] == '\r' && encoded[i + 1] == '\n') {
            trailer_line_end = i;
            break;
          }
        }
        if (trailer_line_end == std::string::npos) return false;

        // 空行 → trailer 段结束
        if (trailer_line_end == pos) {
          pos += 2;
          return true;
        }

        // 解析 trailer 头部行（格式: name: value）
        std::string trailer_line(encoded.begin() + static_cast<std::ptrdiff_t>(pos),
                                  encoded.begin() + static_cast<std::ptrdiff_t>(trailer_line_end));
        auto colon = trailer_line.find(':');
        if (colon == std::string::npos) return false;
        trailers.emplace_back(core::trim(trailer_line.substr(0, colon)),
                              core::trim(trailer_line.substr(colon + 1)));
        pos = trailer_line_end + 2;
      }
      return false;
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

bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded) {
  Headers unused;
  return decode_chunked_body(encoded, decoded, unused);
}

// RFC 7230 section 4.1.2: 禁止出现在 trailer 中的头部字段
bool is_disallowed_trailer_field(const std::string& name) {
  static const std::vector<std::string> disallowed = {
    "transfer-encoding", "content-length", "host",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "upgrade"
  };
  auto lower_name = core::to_lower(name);
  for (const auto& d : disallowed) {
    if (lower_name == d) return true;
  }
  return false;
}

std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, std::size_t chunk_size) {
  Headers empty_trailers;
  return encode_chunked_body(body, empty_trailers, chunk_size);
}

std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, const Headers& trailers, std::size_t chunk_size) {
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
  // 终止块: 0\r\n
  out.push_back('0');
  out.push_back('\r');
  out.push_back('\n');
  // Trailer 段: 跳过禁止字段后逐行写入，最后以空行 \r\n 结束
  for (const auto& [k, v] : trailers) {
    if (is_disallowed_trailer_field(k)) continue;
    out.insert(out.end(), k.begin(), k.end());
    out.push_back(':');
    out.push_back(' ');
    out.insert(out.end(), v.begin(), v.end());
    out.push_back('\r');
    out.push_back('\n');
  }
  out.push_back('\r');
  out.push_back('\n');
  return out;
}

std::string serialize_request(const HttpRequest& req) {
  std::ostringstream os;
  os << req.method << ' ' << req.uri << ' ' << req.version << "\r\n";
  for (const auto& [k, v] : req.headers) os << k << ": " << v << "\r\n";
  os << "\r\n";
  TransferEncodingMode transfer_encoding_mode = TransferEncodingMode::None;
  if (parse_transfer_encoding_mode(req.headers, transfer_encoding_mode) &&
      transfer_encoding_mode == TransferEncodingMode::Chunked) {
    auto encoded = encode_chunked_body(req.body, req.trailers);
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
  TransferEncodingMode transfer_encoding_mode = TransferEncodingMode::None;
  if (parse_transfer_encoding_mode(resp.headers, transfer_encoding_mode) &&
      transfer_encoding_mode == TransferEncodingMode::Chunked) {
    auto encoded = encode_chunked_body(resp.body, resp.trailers);
    os.write(reinterpret_cast<const char*>(encoded.data()), static_cast<std::streamsize>(encoded.size()));
  } else {
    os.write(reinterpret_cast<const char*>(resp.body.data()), static_cast<std::streamsize>(resp.body.size()));
  }
  return os.str();
}

bool message_should_close(const std::string& version, const Headers& headers) {
  auto connection = core::to_lower(header_get(headers, "Connection"));
  if (connection.find("close") != std::string::npos) return true;
  if (version == "HTTP/1.0") return connection.find("keep-alive") == std::string::npos;
  return false;
}

}  // namespace openscanproxy::http
