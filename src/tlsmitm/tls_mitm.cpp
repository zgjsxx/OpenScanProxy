#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include <openssl/pem.h>

namespace openscanproxy::tlsmitm {

TLSMitmEngine::TLSMitmEngine() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}

TLSMitmEngine::~TLSMitmEngine() = default;

void TLSMitmEngine::CtxDeleter::operator()(SSL_CTX* p) const {
  if (p) SSL_CTX_free(p);
}

bool TLSMitmEngine::initialize(const std::string& ca_cert_path, const std::string& ca_key_path) {
  ca_cert_path_ = ca_cert_path;
  ca_key_path_ = ca_key_path;
  client_ctx_.reset(SSL_CTX_new(TLS_server_method()));
  upstream_ctx_.reset(SSL_CTX_new(TLS_client_method()));
  if (!client_ctx_ || !upstream_ctx_) return false;
  // MVP: load CA cert/key directly as server cert for initial MITM bootstrap.
  if (SSL_CTX_use_certificate_file(client_ctx_.get(), ca_cert_path.c_str(), SSL_FILETYPE_PEM) != 1) return false;
  if (SSL_CTX_use_PrivateKey_file(client_ctx_.get(), ca_key_path.c_str(), SSL_FILETYPE_PEM) != 1) return false;
  return true;
}

bool TLSMitmEngine::issue_leaf_for_host(const std::string&, const std::string&, const std::string&) {
  // TODO: implement real per-host dynamic leaf cert issuance and cache.
  return true;
}

}  // namespace openscanproxy::tlsmitm
