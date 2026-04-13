#pragma once

#include "openscanproxy/proxy/runtime.hpp"

namespace openscanproxy::auth {

class AuthPortalServer {
 public:
  explicit AuthPortalServer(proxy::Runtime& runtime) : runtime_(runtime) {}
  void run();

 private:
  proxy::Runtime& runtime_;
};

}  // namespace openscanproxy::auth
