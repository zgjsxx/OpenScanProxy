#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::proxy {

class ProxyServer {
 public:
  explicit ProxyServer(Runtime& runtime) : runtime_(runtime) {}
  void run();

 private:
  void handle_client(int cfd, const std::string& client_addr);
  void handle_http_forward(int cfd, const std::string& client_addr, const std::string& raw);
  void handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr);
  Runtime& runtime_;
};

}  // namespace openscanproxy::proxy
