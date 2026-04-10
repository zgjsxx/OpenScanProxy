#include "openscanproxy/admin/admin_server.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/scanner/scanner.hpp"

#include <iostream>
#include <thread>

using namespace openscanproxy;

int main(int argc, char** argv) {
  std::string config_path = argc > 1 ? argv[1] : "configs/config.json";

  try {
    auto cfg = config::ConfigLoader::load_from_file(config_path);
    proxy::Runtime runtime(cfg);

    runtime.scan_ctx.timeout_ms = cfg.scan_timeout_ms;
    if (cfg.scanner_type == "clamav") {
      runtime.scanner = scanner::create_clamav_scanner(cfg.clamav_mode, cfg.clamav_unix_socket, cfg.clamav_host, cfg.clamav_port);
    } else {
      runtime.scanner = scanner::create_mock_scanner();
    }

    std::cout << "admin static dir: " << cfg.admin_static_dir << std::endl;

    if (cfg.enable_https_mitm) {
      if (!runtime.tls_mitm.initialize(cfg.ca_cert_path, cfg.ca_key_path)) {
        std::cerr << "failed to initialize TLS MITM engine" << std::endl;
      }
    }

    proxy::ProxyServer proxy_server(runtime);
    admin::AdminServer admin_server(runtime);

    std::thread t1([&]() { admin_server.run(); });
    std::thread t2([&]() { proxy_server.run(); });

    t1.join();
    t2.join();
  } catch (const std::exception& ex) {
    std::cerr << "fatal: " << ex.what() << std::endl;
    return 1;
  }

  return 0;
}
