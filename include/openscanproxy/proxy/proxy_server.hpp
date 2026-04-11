#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::proxy {

class ProxyServer {
 public:
  explicit ProxyServer(Runtime& runtime) : runtime_(runtime) {}
  void run();

 private:
  void handle_client(int cfd, const std::string& client_addr);
  bool handle_http_forward(int cfd, const std::string& client_addr, const std::string& user, const std::string& raw);
  void handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr, const std::string& user);
  void handle_connect_mitm(int cfd, int sfd, const std::string& host, const std::string& client_addr, const std::string& user);
  Runtime& runtime_;
};

}  // namespace openscanproxy::proxy
