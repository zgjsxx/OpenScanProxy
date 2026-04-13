#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <cstring>
#include <memory>

namespace openscanproxy::tlsmitm {
namespace {
struct X509Deleter {
  void operator()(X509* p) const {
    if (p) X509_free(p);
  }
};
struct EVPKeyDeleter {
  void operator()(EVP_PKEY* p) const {
    if (p) EVP_PKEY_free(p);
  }
};
struct RSADeleter {
  void operator()(RSA* p) const {
    if (p) RSA_free(p);
  }
};
struct BNDeleter {
  void operator()(BIGNUM* p) const {
    if (p) BN_free(p);
  }
};
struct SSLCTXDeleter {
  void operator()(SSL_CTX* p) const {
    if (p) SSL_CTX_free(p);
  }
};

bool add_ext(X509* cert, int nid, const std::string& value, X509* issuer) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  auto* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value.c_str()));
  if (!ext) return false;
  auto rc = X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
  return rc == 1;
}

bool is_ip_literal(const std::string& host) {
  unsigned char buf[sizeof(struct in6_addr)] = {0};
  return inet_pton(AF_INET, host.c_str(), buf) == 1 || inet_pton(AF_INET6, host.c_str(), buf) == 1;
}
}  // namespace

TLSMitmEngine::TLSMitmEngine() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}

TLSMitmEngine::~TLSMitmEngine() {
  if (ca_cert_) X509_free(ca_cert_);
  if (ca_pkey_) EVP_PKEY_free(ca_pkey_);
}

void TLSMitmEngine::CtxDeleter::operator()(SSL_CTX* p) const {
  if (p) SSL_CTX_free(p);
}

bool TLSMitmEngine::initialize(const std::string& ca_cert_path, const std::string& ca_key_path) {
  ca_cert_path_ = ca_cert_path;
  ca_key_path_ = ca_key_path;
  upstream_ctx_.reset(SSL_CTX_new(TLS_client_method()));
  if (!upstream_ctx_) return false;

  FILE* cert_fp = fopen(ca_cert_path.c_str(), "r");
  if (!cert_fp) return false;
  FILE* key_fp = fopen(ca_key_path.c_str(), "r");
  if (!key_fp) {
    fclose(cert_fp);
    return false;
  }

  X509* cert = PEM_read_X509(cert_fp, nullptr, nullptr, nullptr);
  EVP_PKEY* pkey = PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
  fclose(cert_fp);
  fclose(key_fp);
  if (!cert || !pkey) {
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    return false;
  }
  if (ca_cert_) X509_free(ca_cert_);
  if (ca_pkey_) EVP_PKEY_free(ca_pkey_);
  ca_cert_ = cert;
  ca_pkey_ = pkey;
  return true;
}

SSL_CTX* TLSMitmEngine::create_server_ctx_for_host(const std::string& host) const {
  if (!ca_cert_ || !ca_pkey_) return nullptr;
  std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return nullptr;

  std::unique_ptr<EVP_PKEY, EVPKeyDeleter> leaf_pkey(EVP_PKEY_new());
  std::unique_ptr<RSA, RSADeleter> rsa(RSA_new());
  std::unique_ptr<BIGNUM, BNDeleter> e(BN_new());
  if (!leaf_pkey || !rsa || !e) return nullptr;
  if (BN_set_word(e.get(), RSA_F4) != 1) return nullptr;
  if (RSA_generate_key_ex(rsa.get(), 2048, e.get(), nullptr) != 1) return nullptr;
  if (EVP_PKEY_assign_RSA(leaf_pkey.get(), rsa.release()) != 1) return nullptr;

  std::unique_ptr<X509, X509Deleter> leaf(X509_new());
  if (!leaf) return nullptr;
  if (X509_set_version(leaf.get(), 2) != 1) return nullptr;

  ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()), static_cast<long>(std::time(nullptr)));
  X509_gmtime_adj(X509_get_notBefore(leaf.get()), -300);
  X509_gmtime_adj(X509_get_notAfter(leaf.get()), 60L * 60L * 24L * 365L);
  if (X509_set_pubkey(leaf.get(), leaf_pkey.get()) != 1) return nullptr;

  X509_NAME* subject = X509_get_subject_name(leaf.get());
  if (!subject) return nullptr;
  if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(host.c_str()), -1, -1, 0) !=
      1) {
    return nullptr;
  }
  if (X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca_cert_)) != 1) return nullptr;

  if (!add_ext(leaf.get(), NID_basic_constraints, "critical,CA:FALSE", ca_cert_)) return nullptr;
  if (!add_ext(leaf.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment", ca_cert_)) return nullptr;
  if (!add_ext(leaf.get(), NID_ext_key_usage, "serverAuth", ca_cert_)) return nullptr;
  if (!add_ext(leaf.get(), NID_subject_key_identifier, "hash", ca_cert_)) return nullptr;
  if (!add_ext(leaf.get(), NID_authority_key_identifier, "keyid,issuer", ca_cert_)) return nullptr;

  std::string san = (is_ip_literal(host) ? "IP:" : "DNS:") + host;
  if (!add_ext(leaf.get(), NID_subject_alt_name, san, ca_cert_)) return nullptr;
  if (X509_sign(leaf.get(), ca_pkey_, EVP_sha256()) <= 0) return nullptr;

  if (SSL_CTX_use_certificate(ctx.get(), leaf.get()) != 1) return nullptr;
  if (SSL_CTX_use_PrivateKey(ctx.get(), leaf_pkey.get()) != 1) return nullptr;
  if (SSL_CTX_check_private_key(ctx.get()) != 1) return nullptr;

  return ctx.release();
}

bool TLSMitmEngine::issue_leaf_for_host(const std::string&, const std::string&, const std::string&) {
  // TODO: implement real per-host dynamic leaf cert issuance and cache.
  return true;
}

}  // namespace openscanproxy::tlsmitm
