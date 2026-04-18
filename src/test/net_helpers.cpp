#include "openscanproxy/test/net_helpers.hpp"

#include <cstring>
#include <chrono>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #include <netdb.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

namespace openscanproxy::test::net {

void init() {
#ifdef _WIN32
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    // 初始化失败时不做异常抛出，仅打印；测试 fixture 会检查
  }
#endif
}

void cleanup() {
#ifdef _WIN32
  WSACleanup();
#endif
}

ListenResult listen_on_random_port() {
  socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == OSP_SOCKET_INVALID) return {OSP_SOCKET_INVALID, 0};

  // 允许地址重用
  int one = 1;
#ifdef _WIN32
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
#else
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);  // 端口 0 = OS 自动分配
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1

  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    osp_closesocket(fd);
    return {OSP_SOCKET_INVALID, 0};
  }

  if (listen(fd, 16) != 0) {
    osp_closesocket(fd);
    return {OSP_SOCKET_INVALID, 0};
  }

  uint16_t port = get_local_port(fd);
  return {fd, port};
}

AcceptResult accept_client(socket_t listen_fd) {
  sockaddr_in caddr{};
  socklen_t len = sizeof(caddr);
  socket_t cfd = accept(listen_fd, reinterpret_cast<sockaddr*>(&caddr), &len);
  if (cfd == OSP_SOCKET_INVALID) return {OSP_SOCKET_INVALID, ""};

  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
  std::string addr = std::string(ip) + ":" + std::to_string(ntohs(caddr.sin_port));
  return {cfd, addr};
}

socket_t connect_to(const std::string& host, uint16_t port) {
  // 解析主机名
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;

#ifdef _WIN32
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return OSP_SOCKET_INVALID;
#else
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return OSP_SOCKET_INVALID;
#endif

  socket_t fd = OSP_SOCKET_INVALID;
  for (auto* p = res; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd == OSP_SOCKET_INVALID) continue;
    if (connect(fd, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
    osp_closesocket(fd);
    fd = OSP_SOCKET_INVALID;
  }
  freeaddrinfo(res);
  return fd;
}

bool send_all(socket_t fd, const char* data, std::size_t len) {
  std::size_t sent = 0;
  while (sent < len) {
#ifdef _WIN32
    auto n = send(fd, data + sent, static_cast<int>(len - sent), 0);
#else
    auto n = send(fd, data + sent, len - sent, 0);
#endif
    if (n <= 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

int recv_some(socket_t fd, char* buf, std::size_t buf_len, int timeout_ms) {
#ifdef _WIN32
  // Windows: 用 select 实现超时
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  auto ret = select(0, &readfds, nullptr, nullptr, &tv);
  if (ret <= 0) return -1;  // 超时或错误
  return recv(fd, buf, static_cast<int>(buf_len), 0);
#else
  // Linux: 也用 select 实现超时（更安全）
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  auto ret = select(fd + 1, &readfds, nullptr, nullptr, &tv);
  if (ret <= 0) return -1;
  return recv(fd, buf, buf_len, 0);
#endif
}

std::string send_request_and_read_response(const std::string& host, uint16_t port,
                                            const std::string& raw_request, int timeout_ms) {
  auto fd = connect_to(host, port);
  if (fd == OSP_SOCKET_INVALID) return "";

  if (!send_all(fd, raw_request.data(), raw_request.size())) {
    osp_closesocket(fd);
    return "";
  }

  std::string response;
  char buf[8192];
  // 读取直到超时或连接关闭
  while (true) {
    auto n = recv_some(fd, buf, sizeof(buf), timeout_ms);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }

  osp_closesocket(fd);
  return response;
}

uint16_t get_local_port(socket_t fd) {
  sockaddr_in addr{};
  socklen_t len = sizeof(addr);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return 0;
  return ntohs(addr.sin_port);
}

void set_nonblocking(socket_t fd) {
#ifdef _WIN32
  u_long mode = 1;
  ioctlsocket(fd, FIONBIO, &mode);
#else
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
}

void set_blocking(socket_t fd) {
#ifdef _WIN32
  u_long mode = 0;
  ioctlsocket(fd, FIONBIO, &mode);
#else
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#endif
}

}  // namespace openscanproxy::test::net