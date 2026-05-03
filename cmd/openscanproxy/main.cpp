#include "openscanproxy/auth/auth_portal_server.hpp"
#include "openscanproxy/admin/admin_server.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/policy/policy_store.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/scanner/scanner.hpp"

#include <csignal>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <thread>

using namespace openscanproxy;

int main(int argc, char** argv) {
  std::string config_path = argc > 1 ? argv[1] : "configs/config.json";

  try {
    std::signal(SIGPIPE, SIG_IGN);
    auto cfg = config::ConfigLoader::load_from_file(config_path);
    core::app_logger().configure(cfg.app_log_path, cfg.app_log_level, cfg.app_log_max_files, cfg.app_log_max_size_mb);

    // Initialize policy persistence via PostgreSQL
    std::ostringstream conninfo;
    conninfo << "host=" << cfg.db_host
             << " port=" << cfg.db_port
             << " dbname=" << cfg.db_name
             << " user=" << cfg.db_user
             << " password=" << cfg.db_password;
    policy::PolicyStore policy_store(conninfo.str());
    policy_store.init_db();

    // Load policy from database (use defaults if DB is empty)
    policy::PolicyConfig db_policy;
    policy::PolicyStore::ScanPolicy sp;
    if (policy_store.has_policy_data()) {
      db_policy = policy_store.load_policy();
      sp = policy_store.load_scan_policy();
      core::app_logger().log(core::LogLevel::Info, "policy loaded from database");
    } else {
      core::app_logger().log(core::LogLevel::Info, "database is empty, using default policy");
    }

    // Load auth config from database
    policy::PolicyStore::AuthConfig ac;
    if (policy_store.has_auth_config_data()) {
      ac = policy_store.load_auth_config();
      core::app_logger().log(core::LogLevel::Info,
                             "auth config loaded from db: enable=" +
                                 std::string(ac.enable_proxy_auth ? "true" : "false") +
                                 " mode=" + ac.proxy_auth_mode +
                                 " mitm=" + std::string(ac.enable_https_mitm ? "true" : "false"));
    }

    proxy::Runtime runtime(cfg);
    runtime.policy_store = &policy_store;
    runtime.user_groups.load_from_file();
    runtime.policy.update(db_policy);
    runtime.policy.set_user_group_provider(&runtime.user_groups);

    // Apply DB-loaded auth state
    runtime.auth_enabled = ac.enable_proxy_auth;
    runtime.auth_mode = ac.proxy_auth_mode;
    runtime.mitm_enabled = ac.enable_https_mitm;

    // Initialize proxy auth from database
    runtime.proxy_auth.set_store(&policy_store);
    runtime.proxy_auth.set_enabled(ac.enable_proxy_auth);
    runtime.proxy_auth.reload();
    // Seed initial admin from environment variables if no admin exists yet
    const char* seed_user = std::getenv("OSPROXY_INIT_ADMIN_USER");
    const char* seed_pass = std::getenv("OSPROXY_INIT_ADMIN_PASSWORD");
    if (seed_user && seed_pass && seed_user[0] && seed_pass[0]) {
      const char* seed_email = std::getenv("OSPROXY_INIT_ADMIN_EMAIL");
      if (runtime.proxy_auth.seed_initial_admin(seed_user, seed_pass, seed_email ? seed_email : "")) {
        core::app_logger().log(core::LogLevel::Info,
                               std::string("seeded initial admin user: ") + seed_user);
      }
    }

    if (policy::load_domain_categories_from_csv(cfg.domain_category_data_file)) {
      core::app_logger().log(core::LogLevel::Info, "loaded domain categories from: " + cfg.domain_category_data_file);
    } else {
      core::app_logger().log(core::LogLevel::Warn,
                             "failed to load domain categories from: " + cfg.domain_category_data_file);
    }

    runtime.scan_ctx.timeout_ms = sp.scan_timeout_ms;
    runtime.scan_ctx.max_scan_file_size = sp.max_scan_file_size;
    if (cfg.scanner_type == "clamav") {
      runtime.scanner = scanner::create_clamav_scanner(cfg.clamav_mode, cfg.clamav_unix_socket, cfg.clamav_host, cfg.clamav_port);
    } else {
      runtime.scanner = scanner::create_mock_scanner();
    }

    core::app_logger().log(core::LogLevel::Info, "admin static dir: " + cfg.admin_static_dir);

    if (!runtime.tls_mitm.initialize(cfg.ca_cert_path, cfg.ca_key_path, cfg.tls_leaf_cache_enabled, cfg.tls_leaf_cache_dir)) {
      core::app_logger().log(core::LogLevel::Warn, "TLS MITM engine not initialized (CA cert/key not found), portal auth unavailable");
    }

    proxy::ProxyServer proxy_server(runtime);
    admin::AdminServer admin_server(runtime);
    std::thread t1([&]() { admin_server.run(); });
    std::thread t2([&]() { proxy_server.run(); });
    std::thread t3([&]() {
      auth::AuthPortalServer auth_portal_server(runtime);
      auth_portal_server.run();
    });

    t1.join();
    t2.join();
    t3.join();
  } catch (const std::exception& ex) {
    core::app_logger().log(core::LogLevel::Error, std::string("fatal: ") + ex.what());
    return 1;
  }

  return 0;
}
