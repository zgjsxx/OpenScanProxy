#pragma once

#include "openscanproxy/core/types.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <optional>
#include <vector>

namespace openscanproxy::extractor {

// 文件提取器，从 HTTP 请求/响应中提取待扫描的文件
class FileExtractor {
 public:
  // 从上传请求中提取文件
  std::vector<core::ExtractedFile> from_request(const http::HttpRequest& req, const std::string& host) const;
  // 从下载响应中提取文件
  std::vector<core::ExtractedFile> from_response(const http::HttpRequest& req, const http::HttpResponse& resp,
                                                 const std::string& host) const;

 private:
  // 从 Content-Disposition 头部解析文件名
  static std::optional<std::string> filename_from_content_disposition(const std::string& cd);
};

}  // namespace openscanproxy::extractor
