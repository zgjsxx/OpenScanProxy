#include "openscanproxy/scanner/scanner.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>

namespace openscanproxy::scanner {

class ClamAVScanner final : public IScanner {
 public:
  ClamAVScanner(std::string mode, std::string us, std::string host, uint16_t port)
      : mode_(std::move(mode)), unix_socket_(std::move(us)), host_(std::move(host)), port_(port) {}

  const char* name() const override { return "ClamAVScanner"; }

  core::ScanResult scan(const core::ExtractedFile& file, const ScanContext&) override {
    auto begin = std::chrono::steady_clock::now();
    core::ScanResult r;
    r.scanner_name = name();

    int fd = connect_clamd();
    if (fd < 0) {
      r.status = core::ScanStatus::Error;
      r.error = "failed to connect clamd";
      return r;
    }

    std::string in = "zINSTREAM\0";
    if (::send(fd, in.data(), in.size(), 0) < 0) {
      r.status = core::ScanStatus::Error;
      r.error = "send INSTREAM failed";
      ::close(fd);
      return r;
    }

    uint32_t chunk_len_n = htonl(static_cast<uint32_t>(file.bytes.size()));
    if (::send(fd, &chunk_len_n, sizeof(chunk_len_n), 0) < 0 ||
        ::send(fd, file.bytes.data(), file.bytes.size(), 0) < 0) {
      r.status = core::ScanStatus::Error;
      r.error = "stream bytes failed";
      ::close(fd);
      return r;
    }
    uint32_t z = 0;
    ::send(fd, &z, sizeof(z), 0);

    char buf[1024] = {0};
    auto n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    ::close(fd);
    if (n <= 0) {
      r.status = core::ScanStatus::Error;
      r.error = "empty clamd response";
      return r;
    }

    std::string resp(buf, n);
    if (resp.find("OK") != std::string::npos) {
      r.status = core::ScanStatus::Clean;
    } else if (resp.find("FOUND") != std::string::npos) {
      r.status = core::ScanStatus::Infected;
      auto p = resp.find(':');
      auto q = resp.find("FOUND");
      if (p != std::string::npos && q != std::string::npos && q > p) r.signature = resp.substr(p + 1, q - p - 1);
    } else {
      r.status = core::ScanStatus::Error;
      r.error = resp;
    }
    r.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    return r;
  }

 private:
  int connect_clamd() {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (mode_ == "unix") {
      if (fd < 0) return -1;
      sockaddr_un addr{};
      addr.sun_family = AF_UNIX;
      std::strncpy(addr.sun_path, unix_socket_.c_str(), sizeof(addr.sun_path) - 1);
      if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
      }
      return fd;
    }
    if (fd >= 0) ::close(fd);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1) {
      ::close(fd);
      return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      ::close(fd);
      return -1;
    }
    return fd;
  }

  std::string mode_;
  std::string unix_socket_;
  std::string host_;
  uint16_t port_;
};

std::unique_ptr<IScanner> create_clamav_scanner(const std::string& mode, const std::string& unix_socket,
                                                const std::string& host, uint16_t port) {
  return std::make_unique<ClamAVScanner>(mode, unix_socket, host, port);
}

}  // namespace openscanproxy::scanner
