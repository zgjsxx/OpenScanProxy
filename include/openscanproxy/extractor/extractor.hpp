#pragma once

#include "openscanproxy/core/types.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <optional>
#include <vector>

namespace openscanproxy::extractor {

class FileExtractor {
 public:
  std::vector<core::ExtractedFile> from_request(const http::HttpRequest& req, const std::string& host) const;
  std::vector<core::ExtractedFile> from_response(const http::HttpRequest& req, const http::HttpResponse& resp,
                                                 const std::string& host) const;

 private:
  static std::optional<std::string> filename_from_content_disposition(const std::string& cd);
};

}  // namespace openscanproxy::extractor
