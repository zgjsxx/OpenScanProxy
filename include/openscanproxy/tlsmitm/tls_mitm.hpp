#pragma once

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>

namespace openscanproxy::tlsmitm {

class TLSMitmEngine {
 public:
  TLSMitmEngine();
  ~TLSMitmEngine();

  bool initialize(const std::string& ca_cert_path, const std::string& ca_key_path, bool leaf_cache_enabled = true,
                  const std::string& leaf_cache_dir = "./certs/cache");
  SSL_CTX* client_ctx() const { return client_ctx_.get(); }
  SSL_CTX* upstream_ctx() const { return upstream_ctx_.get(); }
  SSL_CTX* create_server_ctx_for_host(const std::string& host) const;

  bool issue_leaf_for_host(const std::string& host, const std::string& cert_out, const std::string& key_out);

 private:
  struct CtxDeleter {
    void operator()(SSL_CTX* p) const;
  };
  std::unique_ptr<SSL_CTX, CtxDeleter> client_ctx_;
  std::unique_ptr<SSL_CTX, CtxDeleter> upstream_ctx_;
  X509* ca_cert_{nullptr};
  EVP_PKEY* ca_pkey_{nullptr};
  std::string ca_cert_path_;
  std::string ca_key_path_;
  bool leaf_cache_enabled_{true};
  std::string leaf_cache_dir_;
  mutable std::mutex leaf_cache_mu_;
  mutable std::unordered_map<std::string, std::unique_ptr<SSL_CTX, CtxDeleter>> leaf_ctx_cache_;
};

}  // namespace openscanproxy::tlsmitm
