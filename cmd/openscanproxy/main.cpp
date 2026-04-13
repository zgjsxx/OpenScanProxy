#include "openscanproxy/auth/auth_portal_server.hpp"
#include "openscanproxy/admin/admin_server.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/scanner/scanner.hpp"

#include <csignal>
#include <memory>
#include <thread>

using namespace openscanproxy;

int main(int argc, char** argv) {
  std::string config_path = argc > 1 ? argv[1] : "configs/config.json";

  try {
    std::signal(SIGPIPE, SIG_IGN);
    auto cfg = config::ConfigLoader::load_from_file(config_path);
    core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);
    proxy::Runtime runtime(cfg);

    if (policy::load_domain_categories_from_csv(cfg.domain_category_data_file)) {
      core::app_logger().log(core::LogLevel::Info, "loaded domain categories from: " + cfg.domain_category_data_file);
    } else {
      core::app_logger().log(core::LogLevel::Warn,
                             "failed to load domain categories from: " + cfg.domain_category_data_file);
    }

    runtime.scan_ctx.timeout_ms = cfg.scan_timeout_ms;
    if (cfg.scanner_type == "clamav") {
      runtime.scanner = scanner::create_clamav_scanner(cfg.clamav_mode, cfg.clamav_unix_socket, cfg.clamav_host, cfg.clamav_port);
    } else {
      runtime.scanner = scanner::create_mock_scanner();
    }

    core::app_logger().log(core::LogLevel::Info, "admin static dir: " + cfg.admin_static_dir);

    if (cfg.enable_https_mitm) {
      if (!runtime.tls_mitm.initialize(cfg.ca_cert_path, cfg.ca_key_path)) {
        core::app_logger().log(core::LogLevel::Error, "failed to initialize TLS MITM engine");
      }
    }

    proxy::ProxyServer proxy_server(runtime);
    admin::AdminServer admin_server(runtime);
    std::thread t1([&]() { admin_server.run(); });
    std::thread t2([&]() { proxy_server.run(); });
    std::unique_ptr<std::thread> t3;
    if (runtime.portal_auth_enabled()) {
      t3 = std::make_unique<std::thread>([&]() {
        auth::AuthPortalServer auth_portal_server(runtime);
        auth_portal_server.run();
      });
    }

    t1.join();
    t2.join();
    if (t3 && t3->joinable()) t3->join();
  } catch (const std::exception& ex) {
    core::app_logger().log(core::LogLevel::Error, std::string("fatal: ") + ex.what());
    return 1;
  }

  return 0;
}
