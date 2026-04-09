#pragma once

#include <openssl/ssl.h>

#include <memory>
#include <string>

namespace openscanproxy::tlsmitm {

class TLSMitmEngine {
 public:
  TLSMitmEngine();
  ~TLSMitmEngine();

  bool initialize(const std::string& ca_cert_path, const std::string& ca_key_path);
  SSL_CTX* client_ctx() const { return client_ctx_.get(); }
  SSL_CTX* upstream_ctx() const { return upstream_ctx_.get(); }

  bool issue_leaf_for_host(const std::string& host, const std::string& cert_out, const std::string& key_out);

 private:
  struct CtxDeleter {
    void operator()(SSL_CTX* p) const;
  };
  std::unique_ptr<SSL_CTX, CtxDeleter> client_ctx_;
  std::unique_ptr<SSL_CTX, CtxDeleter> upstream_ctx_;
  std::string ca_cert_path_;
  std::string ca_key_path_;
};

}  // namespace openscanproxy::tlsmitm
