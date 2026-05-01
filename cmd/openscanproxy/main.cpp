#include "openscanproxy/auth/auth_portal_server.hpp"
#include "openscanproxy/admin/admin_server.hpp"
#include "openscanproxy/config/config.hpp"
#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/policy/policy_store.hpp"
#include "openscanproxy/proxy/proxy_server.hpp"
#include "openscanproxy/scanner/scanner.hpp"

#include <csignal>
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
    if (policy_store.init_db()) {
      if (policy_store.has_policy_data()) {
        auto db_policy = policy_store.load_policy();
        // Override config fields with DB-loaded policy
        cfg.policy_mode = db_policy.fail_open ? "fail-open" : "fail-close";
        cfg.suspicious_action = db_policy.block_suspicious ? "block" : "log";
        cfg.default_access_action = policy::to_string(db_policy.default_access_action);
        cfg.domain_whitelist = std::move(db_policy.domain_whitelist);
        cfg.domain_blacklist = std::move(db_policy.domain_blacklist);
        cfg.user_whitelist = std::move(db_policy.user_whitelist);
        cfg.user_blacklist = std::move(db_policy.user_blacklist);
        cfg.url_whitelist = std::move(db_policy.url_whitelist);
        cfg.url_blacklist = std::move(db_policy.url_blacklist);
        cfg.url_category_whitelist = std::move(db_policy.url_category_whitelist);
        cfg.url_category_blacklist = std::move(db_policy.url_category_blacklist);
        cfg.access_rules = std::move(db_policy.access_rules);
        auto sp = policy_store.load_scan_policy();
        cfg.scan_upload = sp.scan_upload;
        cfg.scan_download = sp.scan_download;
        cfg.max_scan_file_size = sp.max_scan_file_size;
        cfg.scan_timeout_ms = sp.scan_timeout_ms;
        cfg.allowed_mime = std::move(sp.allowed_mime);
        cfg.allowed_extensions = std::move(sp.allowed_extensions);
        core::app_logger().log(core::LogLevel::Info, "policy loaded from database");
      } else {
        // First run: migrate policy from config.json into the database
        policy::PolicyConfig p{cfg.policy_mode != "fail-close",
                                cfg.suspicious_action == "block",
                                cfg.domain_whitelist,
                                cfg.domain_blacklist,
                                cfg.user_whitelist,
                                cfg.user_blacklist,
                                cfg.url_whitelist,
                                cfg.url_blacklist,
                                cfg.url_category_whitelist,
                                cfg.url_category_blacklist,
                                cfg.access_rules,
                                policy::access_action_from_string(cfg.default_access_action)};
        policy_store.save_policy(p);
        policy::PolicyStore::ScanPolicy sp;
        sp.fail_open = p.fail_open;
        sp.block_suspicious = p.block_suspicious;
        sp.scan_upload = cfg.scan_upload;
        sp.scan_download = cfg.scan_download;
        sp.max_scan_file_size = cfg.max_scan_file_size;
        sp.scan_timeout_ms = cfg.scan_timeout_ms;
        sp.allowed_mime = cfg.allowed_mime;
        sp.allowed_extensions = cfg.allowed_extensions;
        policy_store.save_scan_policy(sp);
        core::app_logger().log(core::LogLevel::Info, "policy migrated from config.json to database");
      }
    } else {
      core::app_logger().log(core::LogLevel::Warn, "policy store init failed, using config.json policy only");
    }

    // Load or migrate auth config
    if (policy_store.has_auth_config_data()) {
      auto db_auth = policy_store.load_auth_config();
      cfg.enable_proxy_auth = db_auth.enable_proxy_auth;
      cfg.proxy_auth_mode = db_auth.proxy_auth_mode;
      cfg.enable_https_mitm = db_auth.enable_https_mitm;
      core::app_logger().log(core::LogLevel::Info,
                             "auth config loaded from db: enable=" +
                                 std::string(db_auth.enable_proxy_auth ? "true" : "false") +
                                 " mode=" + db_auth.proxy_auth_mode +
                                 " mitm=" + std::string(db_auth.enable_https_mitm ? "true" : "false"));
    } else {
      policy_store.save_auth_config(cfg.enable_proxy_auth, cfg.proxy_auth_mode, cfg.enable_https_mitm);
      core::app_logger().log(core::LogLevel::Info, "auth config migrated from config.json to database");
    }

    proxy::Runtime runtime(cfg);
    runtime.policy_store = &policy_store;

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
