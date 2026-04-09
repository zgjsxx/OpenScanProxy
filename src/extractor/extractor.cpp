#include "openscanproxy/extractor/extractor.hpp"

#include "openscanproxy/core/util.hpp"

namespace openscanproxy::extractor {

std::optional<std::string> FileExtractor::filename_from_content_disposition(const std::string& cd) {
  auto pos = cd.find("filename=");
  if (pos == std::string::npos) return std::nullopt;
  std::string v = cd.substr(pos + 9);
  if (!v.empty() && v.front() == '"') v.erase(v.begin());
  if (!v.empty() && v.back() == '"') v.pop_back();
  return v;
}

std::vector<core::ExtractedFile> FileExtractor::from_request(const http::HttpRequest& req, const std::string& host) const {
  std::vector<core::ExtractedFile> out;
  auto ct = http::header_get(req.headers, "Content-Type");
  auto cd = http::header_get(req.headers, "Content-Disposition");

  if (ct.find("multipart/form-data") != std::string::npos || cd.find("filename=") != std::string::npos) {
    core::ExtractedFile f;
    f.filename = filename_from_content_disposition(cd).value_or("upload.bin");
    f.mime = ct.empty() ? "application/octet-stream" : ct;
    f.bytes = req.body;
    f.direction = core::Direction::Upload;
    f.source_url = req.uri;
    f.source_host = host;
    out.push_back(std::move(f));
  }
  return out;
}

std::vector<core::ExtractedFile> FileExtractor::from_response(const http::HttpRequest& req, const http::HttpResponse& resp,
                                                              const std::string& host) const {
  std::vector<core::ExtractedFile> out;
  auto ct = http::header_get(resp.headers, "Content-Type");
  auto cd = http::header_get(resp.headers, "Content-Disposition");

  bool looks_file = cd.find("attachment") != std::string::npos || cd.find("filename=") != std::string::npos ||
                    ct.find("application/") == 0;
  if (looks_file) {
    core::ExtractedFile f;
    f.filename = filename_from_content_disposition(cd).value_or("download.bin");
    f.mime = ct.empty() ? "application/octet-stream" : ct;
    f.bytes = resp.body;
    f.direction = core::Direction::Download;
    f.source_url = req.uri;
    f.source_host = host;
    out.push_back(std::move(f));
  }
  return out;
}

}  // namespace openscanproxy::extractor
