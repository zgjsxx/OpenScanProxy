#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::proxy {

// 代理服务器，处理所有 HTTP/HTTPS 代理请求
class ProxyServer {
 public:
  explicit ProxyServer(Runtime& runtime) : runtime_(runtime) {}
  void run();  // 启动代理服务（阻塞运行）

 private:
  // 处理单个客户端连接（读取请求、认证、转发）
  void handle_client(int cfd, const std::string& client_addr);
  // 处理 HTTP 正向代理请求（GET/POST 等）
  bool handle_http_forward(int cfd, const std::string& client_addr, const std::string& user, const std::string& raw);
  // 处理 HTTPS CONNECT 隧道（不解密，直接双向转发）
  void handle_connect_tunnel(int cfd, const std::string& target, const std::string& client_addr, const std::string& user);
  // 处理 HTTPS MITM 解密代理（中间人方式解密再转发）
  void handle_connect_mitm(int cfd, int sfd, const std::string& host, const std::string& client_addr, const std::string& user);
  Runtime& runtime_;
};

}  // namespace openscanproxy::proxy
