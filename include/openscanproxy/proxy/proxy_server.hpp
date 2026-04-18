#pragma once

#include "openscanproxy/proxy/runtime.hpp"

#include <atomic>

namespace openscanproxy::proxy {

class ProxyServer {
 public:
  explicit ProxyServer(Runtime& runtime) : runtime_(runtime) {}
  void run();
  void stop();

 private:
  void handle_client(int cfd, const std::string& client_addr);
  bool handle_http_forward(int cfd, const std::string& client_addr, const std::string& user, const std::string& raw);
  void handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr, const std::string& user);
  void handle_connect_mitm(int cfd, int sfd, const std::string& host, const std::string& client_addr, const std::string& user);

  Runtime& runtime_;
  std::atomic<bool> running_{false};
  int listen_fd_{-1};
};

}  // namespace openscanproxy::proxy
