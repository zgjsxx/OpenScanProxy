#pragma once

// 跨平台 socket / 网络辅助函数，用于集成测试。
// Windows 使用 Winsock2，Linux/Unix 使用 POSIX socket。

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
  typedef int socklen_t;
  // Windows 下 SOCKET 是 unsigned，POSIX 下是 int；统一用 socket_t
  typedef SOCKET socket_t;
  #define OSP_SOCKET_INVALID INVALID_SOCKET
  // Windows close socket 用 closesocket，POSIX 用 close
  #define osp_closesocket closesocket
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #include <netdb.h>
  typedef int socket_t;
  #define OSP_SOCKET_INVALID (-1)
  #define osp_closesocket close
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace openscanproxy::test::net {

// Winsock 初始化 / 清理（Windows 下必须调用，Linux 下为空操作）
void init();
void cleanup();

// 创建 TCP 监听 socket，绑定到 127.0.0.1:0（OS 自动分配端口）
// 返回 {listen_fd, actual_port}
struct ListenResult {
  socket_t fd;
  uint16_t port;
};
ListenResult listen_on_random_port();

// 接受一个客户端连接（阻塞），返回 {client_fd, client_addr_str}
struct AcceptResult {
  socket_t fd;
  std::string addr;
};
AcceptResult accept_client(socket_t listen_fd);

// 连接到指定 host:port（阻塞）
socket_t connect_to(const std::string& host, uint16_t port);

// 发送全部数据
bool send_all(socket_t fd, const char* data, std::size_t len);

// 接收数据，返回接收到的字节（0=连接关闭，-1=超时/错误）
int recv_some(socket_t fd, char* buf, std::size_t buf_len, int timeout_ms = 3000);

// 发送原始 HTTP 请求并读取完整 HTTP 响应（简化版：读直到超时或连接关闭）
std::string send_request_and_read_response(const std::string& host, uint16_t port,
                                            const std::string& raw_request, int timeout_ms = 5000);

// 获取 socket 本地端口（用于 listen_on_random_port 后获取实际端口）
uint16_t get_local_port(socket_t fd);

// 设置 socket 为非阻塞（用于超时 recv）
void set_nonblocking(socket_t fd);

// 设置 socket 为阻塞
void set_blocking(socket_t fd);

}  // namespace openscanproxy::test::net