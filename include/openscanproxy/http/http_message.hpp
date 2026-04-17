#pragma once

#include <cstdint>
#include <utility>
#include <string>
#include <vector>

namespace openscanproxy::http {

// HTTP 头部列表类型，保留重复头部（如 Set-Cookie）的顺序
using Headers = std::vector<std::pair<std::string, std::string>>;

// HTTP 请求结构体
struct HttpRequest {
  std::string method;               // 请求方法（GET/POST/CONNECT 等）
  std::string uri;                  // 请求 URI（绝对 URL 或路径形式）
  std::string version{"HTTP/1.1"};  // HTTP 版本
  Headers headers;                  // 请求头部列表
  Headers trailers;                 // chunked 编码的 trailer 头部
  std::vector<uint8_t> body;        // 解码后的请求体
};

// HTTP 响应结构体
struct HttpResponse {
  std::string version{"HTTP/1.1"};  // HTTP 版本
  int status{200};                  // 状态码
  std::string reason{"OK"};         // 状态描述
  Headers headers;                  // 响应头部列表
  Headers trailers;                 // chunked 编码的 trailer 头部
  std::vector<uint8_t> body;        // 解码后的响应体
};

// 获取指定头部名的最后一个值（不区分大小写）
std::string header_get(const Headers& headers, const std::string& key);
// 获取指定头部名的所有值列表（不区分大小写）
std::vector<std::string> header_get_all(const Headers& headers, const std::string& key);
// 添加一个头部（保留已有同名头部）
void header_add(Headers& headers, std::string key, std::string value);
// 设置一个头部（先删除所有同名头部再添加）
void header_set(Headers& headers, std::string key, std::string value);
// 删除所有指定名的头部（不区分大小写）
void header_erase(Headers& headers, const std::string& key);

// 将请求序列化为 HTTP 线路格式字符串
std::string serialize_request(const HttpRequest& req);
// 将响应序列化为 HTTP 线路格式字符串
std::string serialize_response(const HttpResponse& resp);

// 解析原始 HTTP 请求字符串
bool parse_request(const std::string& raw, HttpRequest& req);
// 解析原始 HTTP 响应字符串
bool parse_response(const std::string& raw, HttpResponse& resp);
// 解析请求并返回消费的字节数（支持管线化）
bool parse_request(const std::string& raw, HttpRequest& req, std::size_t* consumed);
// 解析响应并返回消费的字节数
bool parse_response(const std::string& raw, HttpResponse& resp, std::size_t* consumed);

// 解码 chunked 编码的正文（不含 trailer）
bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded);
// 解码 chunked 编码的正文，同时提取 trailer 头部
bool decode_chunked_body(const std::vector<uint8_t>& encoded, std::vector<uint8_t>& decoded, Headers& trailers);

// 将正文编码为 chunked 格式（不含 trailer）
std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, std::size_t chunk_size = 4096);
// 将正文编码为 chunked 格式，同时写入 trailer 头部
std::vector<uint8_t> encode_chunked_body(const std::vector<uint8_t>& body, const Headers& trailers, std::size_t chunk_size = 4096);

// 根据 HTTP 版本和 Connection 头判断连接是否应该关闭
bool message_should_close(const std::string& version, const Headers& headers);

}  // namespace openscanproxy::http
