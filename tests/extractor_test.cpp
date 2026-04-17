#include "openscanproxy/extractor/extractor.hpp"
#include "openscanproxy/http/http_message.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool test_request_extractor_uses_filename_from_content_disposition() {
  openscanproxy::http::HttpRequest req;
  req.method = "POST";
  req.uri = "/upload";
  openscanproxy::http::header_add(req.headers, "Content-Type", "multipart/form-data; boundary=abc");
  openscanproxy::http::header_add(req.headers, "Content-Disposition", "form-data; name=\"file\"; filename=\"report.pdf\"");
  req.body = std::vector<uint8_t>{'P', 'D', 'F'};

  openscanproxy::extractor::FileExtractor extractor;
  const auto files = extractor.from_request(req, "files.example.com");
  return expect(files.size() == 1, "request extractor finds upload") &&
         expect(files[0].filename == "report.pdf", "request extractor keeps content-disposition filename") &&
         expect(files[0].mime == "multipart/form-data; boundary=abc", "request extractor keeps request mime") &&
         expect(files[0].direction == openscanproxy::core::Direction::Upload, "request direction is upload") &&
         expect(files[0].source_url == "/upload" && files[0].source_host == "files.example.com",
                "request source metadata populated") &&
         expect(files[0].bytes == req.body, "request body copied into extracted file");
}

bool test_request_extractor_falls_back_to_default_filename() {
  openscanproxy::http::HttpRequest req;
  req.uri = "/api/upload";
  openscanproxy::http::header_add(req.headers, "Content-Type", "multipart/form-data");
  req.body = std::vector<uint8_t>{'x'};

  openscanproxy::extractor::FileExtractor extractor;
  const auto files = extractor.from_request(req, "upload.example.com");
  return expect(files.size() == 1, "multipart request still extracts file") &&
         expect(files[0].filename == "upload.bin", "request extractor falls back to upload.bin without filename");
}

bool test_request_extractor_ignores_non_file_payloads() {
  openscanproxy::http::HttpRequest req;
  req.uri = "/submit";
  openscanproxy::http::header_add(req.headers, "Content-Type", "application/json");
  req.body = std::vector<uint8_t>{'{', '}'};

  openscanproxy::extractor::FileExtractor extractor;
  return expect(extractor.from_request(req, "api.example.com").empty(), "non multipart request is ignored");
}

bool test_response_extractor_detects_attachment_download() {
  openscanproxy::http::HttpRequest req;
  req.uri = "/download/42";

  openscanproxy::http::HttpResponse resp;
  openscanproxy::http::header_add(resp.headers, "Content-Type", "text/plain");
  openscanproxy::http::header_add(resp.headers, "Content-Disposition", "attachment; filename=\"notes.txt\"");
  resp.body = std::vector<uint8_t>{'n', 'o', 't', 'e'};

  openscanproxy::extractor::FileExtractor extractor;
  const auto files = extractor.from_response(req, resp, "cdn.example.com");
  return expect(files.size() == 1, "attachment response extracts file") &&
         expect(files[0].filename == "notes.txt", "response extractor keeps attachment filename") &&
         expect(files[0].mime == "text/plain", "response extractor keeps response mime") &&
         expect(files[0].direction == openscanproxy::core::Direction::Download, "response direction is download") &&
         expect(files[0].source_url == "/download/42" && files[0].source_host == "cdn.example.com",
                "response source metadata populated") &&
         expect(files[0].bytes == resp.body, "response body copied into extracted file");
}

bool test_response_extractor_detects_application_content_without_attachment() {
  openscanproxy::http::HttpRequest req;
  req.uri = "/pkg";

  openscanproxy::http::HttpResponse resp;
  openscanproxy::http::header_add(resp.headers, "Content-Type", "application/octet-stream");
  resp.body = std::vector<uint8_t>{0x01, 0x02};

  openscanproxy::extractor::FileExtractor extractor;
  const auto files = extractor.from_response(req, resp, "repo.example.com");
  return expect(files.size() == 1, "application response is treated as download") &&
         expect(files[0].filename == "download.bin", "response extractor falls back to download.bin");
}

bool test_response_extractor_ignores_inline_text_content() {
  openscanproxy::http::HttpRequest req;
  req.uri = "/index.html";

  openscanproxy::http::HttpResponse resp;
  openscanproxy::http::header_add(resp.headers, "Content-Type", "text/html");
  resp.body = std::vector<uint8_t>{'<', 'h', '1', '>'};

  openscanproxy::extractor::FileExtractor extractor;
  return expect(extractor.from_response(req, resp, "www.example.com").empty(),
                "inline text response is not treated as downloadable file");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_request_extractor_uses_filename_from_content_disposition() && ok;
  ok = test_request_extractor_falls_back_to_default_filename() && ok;
  ok = test_request_extractor_ignores_non_file_payloads() && ok;
  ok = test_response_extractor_detects_attachment_download() && ok;
  ok = test_response_extractor_detects_application_content_without_attachment() && ok;
  ok = test_response_extractor_ignores_inline_text_content() && ok;
  if (ok) {
    std::cout << "All extractor tests passed\n";
    return 0;
  }
  return 1;
}
