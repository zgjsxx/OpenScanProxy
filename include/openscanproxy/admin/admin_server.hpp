#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::admin {

// 管理后台 HTTP 服务器，提供统计查询、策略更新等 API
class AdminServer {
 public:
  explicit AdminServer(proxy::Runtime& runtime) : runtime_(runtime) {}
  void run();  // 启动管理后台服务（阻塞运行）

 private:
  proxy::Runtime& runtime_;
};

}  // namespace openscanproxy::admin
