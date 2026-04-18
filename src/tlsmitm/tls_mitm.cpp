#include "openscanproxy/tlsmitm/tls_mitm.hpp"

#include "openscanproxy/core/logger.hpp"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>

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

std::string hex_encode(const std::string& text) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size() * 2);
  for (unsigned char c : text) {
    out.push_back(kHex[(c >> 4) & 0xF]);
    out.push_back(kHex[c & 0xF]);
  }
  return out;
}

std::string safe_host_cache_name(const std::string& host) {
  return hex_encode(host);
}

std::string read_all_text(const std::filesystem::path& path) {
  std::ifstream ifs(path, std::ios::binary);
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

bool write_text_file(const std::filesystem::path& path, const std::string& content) {
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  if (!ofs) return false;
  ofs << content;
  return static_cast<bool>(ofs);
}

bool pem_encode_cert(X509* cert, std::string& out) {
  if (!cert) return false;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio) return false;
  if (PEM_write_bio_X509(bio.get(), cert) != 1) return false;
  char* data = nullptr;
  auto size = BIO_get_mem_data(bio.get(), &data);
  if (size <= 0 || data == nullptr) return false;
  out.assign(data, static_cast<std::size_t>(size));
  return true;
}

bool pem_encode_key(EVP_PKEY* key, std::string& out) {
  if (!key) return false;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio) return false;
  if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) return false;
  char* data = nullptr;
  auto size = BIO_get_mem_data(bio.get(), &data);
  if (size <= 0 || data == nullptr) return false;
  out.assign(data, static_cast<std::size_t>(size));
  return true;
}

X509* load_cert_from_pem(const std::string& pem) {
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  if (!bio) return nullptr;
  return PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
}

EVP_PKEY* load_key_from_pem(const std::string& pem) {
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  if (!bio) return nullptr;
  return PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
}

SSL_CTX* build_server_ctx_from_material(X509* cert, EVP_PKEY* key) {
  if (!cert || !key) return nullptr;
  std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(SSL_CTX_new(TLS_server_method()));
  if (!ctx) return nullptr;
  if (SSL_CTX_use_certificate(ctx.get(), cert) != 1) return nullptr;
  if (SSL_CTX_use_PrivateKey(ctx.get(), key) != 1) return nullptr;
  if (SSL_CTX_check_private_key(ctx.get()) != 1) return nullptr;
  return ctx.release();
}

bool build_leaf_material(const std::string& host, X509* ca_cert, EVP_PKEY* ca_pkey,
                         std::unique_ptr<X509, X509Deleter>& leaf,
                         std::unique_ptr<EVP_PKEY, EVPKeyDeleter>& leaf_pkey) {
  if (!ca_cert || !ca_pkey) return false;

  leaf_pkey.reset(EVP_PKEY_new());
  std::unique_ptr<RSA, RSADeleter> rsa(RSA_new());
  std::unique_ptr<BIGNUM, BNDeleter> e(BN_new());
  if (!leaf_pkey || !rsa || !e) return false;
  if (BN_set_word(e.get(), RSA_F4) != 1) return false;
  if (RSA_generate_key_ex(rsa.get(), 2048, e.get(), nullptr) != 1) return false;
  if (EVP_PKEY_assign_RSA(leaf_pkey.get(), rsa.release()) != 1) return false;

  leaf.reset(X509_new());
  if (!leaf) return false;
  if (X509_set_version(leaf.get(), 2) != 1) return false;

  ASN1_INTEGER_set(X509_get_serialNumber(leaf.get()), static_cast<long>(std::time(nullptr)));
  X509_gmtime_adj(X509_get_notBefore(leaf.get()), -300);
  X509_gmtime_adj(X509_get_notAfter(leaf.get()), 60L * 60L * 24L * 365L);
  if (X509_set_pubkey(leaf.get(), leaf_pkey.get()) != 1) return false;

  X509_NAME* subject = X509_get_subject_name(leaf.get());
  if (!subject) return false;
  if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(host.c_str()), -1, -1, 0) != 1) {
    return false;
  }
  if (X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca_cert)) != 1) return false;

  if (!add_ext(leaf.get(), NID_basic_constraints, "critical,CA:FALSE", ca_cert)) return false;
  if (!add_ext(leaf.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment", ca_cert)) return false;
  if (!add_ext(leaf.get(), NID_ext_key_usage, "serverAuth", ca_cert)) return false;
  if (!add_ext(leaf.get(), NID_subject_key_identifier, "hash", ca_cert)) return false;
  if (!add_ext(leaf.get(), NID_authority_key_identifier, "keyid,issuer", ca_cert)) return false;

  std::string san = (is_ip_literal(host) ? "IP:" : "DNS:") + host;
  if (!add_ext(leaf.get(), NID_subject_alt_name, san, ca_cert)) return false;
  if (X509_sign(leaf.get(), ca_pkey, EVP_sha256()) <= 0) return false;
  return true;
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

bool TLSMitmEngine::initialize(const std::string& ca_cert_path, const std::string& ca_key_path, bool leaf_cache_enabled,
                               const std::string& leaf_cache_dir) {
  ca_cert_path_ = ca_cert_path;
  ca_key_path_ = ca_key_path;
  leaf_cache_enabled_ = leaf_cache_enabled;
  leaf_cache_dir_ = leaf_cache_dir;
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

  if (!leaf_cache_enabled_) return true;

  try {
    std::filesystem::create_directories(leaf_cache_dir_);
  } catch (const std::exception& ex) {
    core::app_logger().log(core::LogLevel::Warn, std::string("tls leaf cache: failed to create cache dir: ") + ex.what());
    return true;
  }

  try {
    for (const auto& entry : std::filesystem::directory_iterator(leaf_cache_dir_)) {
      if (!entry.is_regular_file()) continue;
      auto path = entry.path();
      auto name = path.filename().string();
      if (name.size() <= 8 || name.substr(name.size() - 8) != ".crt.pem") continue;
      auto base = name.substr(0, name.size() - 8);
      auto key_path = std::filesystem::path(leaf_cache_dir_) / (base + ".key.pem");
      if (!std::filesystem::exists(key_path)) {
        core::app_logger().log(core::LogLevel::Warn, "tls leaf cache: missing key for " + name);
        continue;
      }
      auto cert_pem = read_all_text(path);
      auto key_pem = read_all_text(key_path);
      std::unique_ptr<X509, X509Deleter> leaf(load_cert_from_pem(cert_pem));
      std::unique_ptr<EVP_PKEY, EVPKeyDeleter> leaf_key(load_key_from_pem(key_pem));
      std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(build_server_ctx_from_material(leaf.get(), leaf_key.get()));
      if (!leaf || !leaf_key || !ctx) {
        core::app_logger().log(core::LogLevel::Warn, "tls leaf cache: failed to load cached cert/key pair " + base);
        continue;
      }
      std::lock_guard<std::mutex> lk(leaf_cache_mu_);
      leaf_ctx_cache_[base] = std::unique_ptr<SSL_CTX, CtxDeleter>(ctx.release());
      core::app_logger().log(core::LogLevel::Info, "tls leaf cache: loaded cached leaf ctx " + base);
    }
  } catch (const std::exception& ex) {
    core::app_logger().log(core::LogLevel::Warn, std::string("tls leaf cache: preload failed: ") + ex.what());
  }
  return true;
}

SSL_CTX* TLSMitmEngine::create_server_ctx_for_host(const std::string& host) const {
  if (!ca_cert_ || !ca_pkey_) return nullptr;
  const auto cache_key = safe_host_cache_name(host);

  if (leaf_cache_enabled_) {
    std::lock_guard<std::mutex> lk(leaf_cache_mu_);
    auto it = leaf_ctx_cache_.find(cache_key);
    if (it != leaf_ctx_cache_.end()) {
      SSL_CTX_up_ref(it->second.get());
      core::app_logger().log(core::LogLevel::Debug, "tls leaf cache: memory hit for " + host);
      return it->second.get();
    }

    auto cert_path = std::filesystem::path(leaf_cache_dir_) / (cache_key + ".crt.pem");
    auto key_path = std::filesystem::path(leaf_cache_dir_) / (cache_key + ".key.pem");
    if (std::filesystem::exists(cert_path) && std::filesystem::exists(key_path)) {
      auto cert_pem = read_all_text(cert_path);
      auto key_pem = read_all_text(key_path);
      std::unique_ptr<X509, X509Deleter> leaf(load_cert_from_pem(cert_pem));
      std::unique_ptr<EVP_PKEY, EVPKeyDeleter> leaf_key(load_key_from_pem(key_pem));
      std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(build_server_ctx_from_material(leaf.get(), leaf_key.get()));
      if (leaf && leaf_key && ctx) {
        auto* raw = ctx.get();
        SSL_CTX_up_ref(raw);
        leaf_ctx_cache_[cache_key] = std::unique_ptr<SSL_CTX, CtxDeleter>(ctx.release());
        core::app_logger().log(core::LogLevel::Info, "tls leaf cache: disk hit for " + host);
        return raw;
      }
      core::app_logger().log(core::LogLevel::Warn, "tls leaf cache: disk load failed for " + host);
    }

    std::unique_ptr<X509, X509Deleter> leaf;
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> leaf_pkey;
    if (!build_leaf_material(host, ca_cert_, ca_pkey_, leaf, leaf_pkey)) return nullptr;

    std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(build_server_ctx_from_material(leaf.get(), leaf_pkey.get()));
    if (!ctx) return nullptr;

    std::string cert_pem;
    std::string key_pem;
    if (pem_encode_cert(leaf.get(), cert_pem) && pem_encode_key(leaf_pkey.get(), key_pem)) {
      try {
        std::filesystem::create_directories(leaf_cache_dir_);
        if (!write_text_file(cert_path, cert_pem) || !write_text_file(key_path, key_pem)) {
          core::app_logger().log(core::LogLevel::Warn, "tls leaf cache: failed to persist leaf material for " + host);
        }
      } catch (const std::exception& ex) {
        core::app_logger().log(core::LogLevel::Warn,
                               "tls leaf cache: exception while persisting leaf material for " + host + ": " + ex.what());
      }
    }

    auto* raw = ctx.get();
    SSL_CTX_up_ref(raw);
    leaf_ctx_cache_[cache_key] = std::unique_ptr<SSL_CTX, CtxDeleter>(ctx.release());
    core::app_logger().log(core::LogLevel::Info, "tls leaf cache: issued new leaf ctx for " + host);
    return raw;
  }

  std::unique_ptr<X509, X509Deleter> leaf;
  std::unique_ptr<EVP_PKEY, EVPKeyDeleter> leaf_pkey;
  if (!build_leaf_material(host, ca_cert_, ca_pkey_, leaf, leaf_pkey)) return nullptr;

  std::unique_ptr<SSL_CTX, SSLCTXDeleter> ctx(build_server_ctx_from_material(leaf.get(), leaf_pkey.get()));
  if (!ctx) return nullptr;

  core::app_logger().log(core::LogLevel::Info, "tls leaf cache: cache disabled, issued uncached leaf ctx for " + host);
  return ctx.release();
}

bool TLSMitmEngine::issue_leaf_for_host(const std::string&, const std::string&, const std::string&) {
  // TODO: 实现真正的按主机动态叶子证书签发与缓存。
  return true;
}

}  // namespace openscanproxy::tlsmitm
