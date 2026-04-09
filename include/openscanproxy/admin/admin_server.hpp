#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::admin {

class AdminServer {
 public:
  explicit AdminServer(proxy::Runtime& runtime) : runtime_(runtime) {}
  void run();

 private:
  proxy::Runtime& runtime_;
};

}  // namespace openscanproxy::admin
