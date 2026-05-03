#include "openscanproxy/policy/policy_store.hpp"

#include "openscanproxy/core/logger.hpp"
#include "openscanproxy/core/util.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <memory>
#include <sstream>

namespace openscanproxy::policy {

namespace {

using ResultPtr = std::unique_ptr<PGresult, void (*)(PGresult*)>;
ResultPtr make_result(PGresult* r) { return ResultPtr(r, &PQclear); }

ResultPtr exec(PGconn* conn, const std::string& sql) {
  return make_result(PQexec(conn, sql.c_str()));
}

bool ok(PGresult* r) {
  auto s = PQresultStatus(r);
  return s == PGRES_COMMAND_OK || s == PGRES_TUPLES_OK;
}

std::string escape_literal(PGconn* conn, const std::string& s) {
  char* esc = PQescapeLiteral(conn, s.c_str(), s.size());
  std::string out(esc);
  PQfreemem(esc);
  return out;
}

std::string json_array(const std::vector<std::string>& values) {
  std::ostringstream os;
  os << "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i) os << ",";
    os << "\"" << core::json_escape(values[i]) << "\"";
  }
  os << "]";
  return os.str();
}

// Simple JSON array parser — extracts quoted strings from a JSON array like ["a","b"]
std::vector<std::string> parse_json_string_array(const char* val) {
  std::vector<std::string> out;
  if (!val || !*val) return out;
  std::string s(val);
  // Find all quoted strings
  for (std::size_t i = 0; i < s.size(); ) {
    auto q = s.find('"', i);
    if (q == std::string::npos) break;
    auto q2 = s.find('"', q + 1);
    if (q2 == std::string::npos) break;
    out.push_back(s.substr(q + 1, q2 - q - 1));
    i = q2 + 1;
  }
  return out;
}

}  // namespace

PolicyStore::PolicyStore(const std::string& conninfo) {
  conn_ = PQconnectdb(conninfo.c_str());
  if (PQstatus(conn_) != CONNECTION_OK) {
    core::app_logger().log(core::LogLevel::Error,
                           "policy store: connection failed: " + std::string(PQerrorMessage(conn_)));
    PQfinish(conn_);
    conn_ = nullptr;
  }
}

PolicyStore::~PolicyStore() {
  if (conn_) PQfinish(conn_);
}

std::string PolicyStore::pq_escape_literal(const std::string& s) { return escape_literal(conn_, s); }
std::string PolicyStore::pq_escape_identifier(const std::string& s) {
  char* esc = PQescapeIdentifier(conn_, s.c_str(), s.size());
  std::string out(esc);
  PQfreemem(esc);
  return out;
}

bool PolicyStore::exec_simple(const std::string& sql) {
  auto r = exec(conn_, sql);
  return ok(r.get());
}

std::string PolicyStore::query_one_string(const std::string& sql, const std::string& field) {
  auto r = exec(conn_, sql);
  if (!ok(r.get()) || PQntuples(r.get()) == 0) return "";
  int col = PQfnumber(r.get(), field.c_str());
  if (col < 0) return "";
  auto val = PQgetvalue(r.get(), 0, col);
  return val ? std::string(val) : "";
}

std::vector<std::string> PolicyStore::query_string_list(const std::string& sql) {
  std::vector<std::string> out;
  auto r = exec(conn_, sql);
  if (!ok(r.get())) return out;
  int n = PQntuples(r.get());
  for (int i = 0; i < n; ++i) {
    auto val = PQgetvalue(r.get(), i, 0);
    if (val) out.push_back(val);
  }
  return out;
}

bool PolicyStore::init_db() {
  if (!conn_) return false;
  const char* ddl = R"SQL(
CREATE TABLE IF NOT EXISTS policy_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    policy_mode         TEXT NOT NULL DEFAULT 'fail-open',
    suspicious_action   TEXT NOT NULL DEFAULT 'log',
    default_access_action TEXT NOT NULL DEFAULT 'allow',
    scan_upload         BOOLEAN NOT NULL DEFAULT true,
    scan_download       BOOLEAN NOT NULL DEFAULT true,
    max_scan_file_size  INTEGER NOT NULL DEFAULT 5242880,
    scan_timeout_ms     INTEGER NOT NULL DEFAULT 5000
);

CREATE TABLE IF NOT EXISTS policy_lists (
    id          SERIAL PRIMARY KEY,
    list_type   TEXT NOT NULL,
    value       TEXT NOT NULL,
    UNIQUE (list_type, value)
);

CREATE INDEX IF NOT EXISTS idx_policy_lists_type ON policy_lists (list_type);

CREATE TABLE IF NOT EXISTS access_rules (
    id                      SERIAL PRIMARY KEY,
    rule_order              INTEGER NOT NULL,
    name                    TEXT NOT NULL DEFAULT '',
    domain_whitelist        JSONB NOT NULL DEFAULT '[]',
    domain_blacklist        JSONB NOT NULL DEFAULT '[]',
    url_whitelist           JSONB NOT NULL DEFAULT '[]',
    url_blacklist           JSONB NOT NULL DEFAULT '[]',
    url_category_whitelist  JSONB NOT NULL DEFAULT '[]',
    url_category_blacklist  JSONB NOT NULL DEFAULT '[]',
    users                   JSONB NOT NULL DEFAULT '[]',
    groups                  JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_access_rules_order ON access_rules (rule_order);

CREATE TABLE IF NOT EXISTS auth_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    enable_proxy_auth   BOOLEAN NOT NULL DEFAULT false,
    proxy_auth_mode     TEXT NOT NULL DEFAULT 'basic',
    enable_https_mitm   BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS proxy_users (
    username    TEXT PRIMARY KEY,
    password    TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'user',
    groups      JSONB NOT NULL DEFAULT '[]'
);
)SQL";
  return exec_simple(ddl);
}

bool PolicyStore::has_policy_data() {
  if (!conn_) return false;
  auto v = query_one_string("SELECT id FROM policy_config WHERE id = 1", "id");
  return !v.empty();
}

PolicyStore::ScanPolicy PolicyStore::load_scan_policy() {
  ScanPolicy sp;
  if (!conn_) return sp;

  auto pm = query_one_string("SELECT policy_mode FROM policy_config WHERE id = 1", "policy_mode");
  sp.fail_open = (pm != "fail-close");

  auto sa = query_one_string("SELECT suspicious_action FROM policy_config WHERE id = 1", "suspicious_action");
  sp.block_suspicious = (sa == "block");

  auto su = query_one_string("SELECT scan_upload FROM policy_config WHERE id = 1", "scan_upload");
  sp.scan_upload = (su != "f");

  auto sd = query_one_string("SELECT scan_download FROM policy_config WHERE id = 1", "scan_download");
  sp.scan_download = (sd != "f");

  auto mfs = query_one_string("SELECT max_scan_file_size FROM policy_config WHERE id = 1", "max_scan_file_size");
  if (!mfs.empty()) {
    try { sp.max_scan_file_size = static_cast<std::size_t>(std::stoull(mfs)); } catch (...) {}
  }

  auto sto = query_one_string("SELECT scan_timeout_ms FROM policy_config WHERE id = 1", "scan_timeout_ms");
  if (!sto.empty()) {
    try { sp.scan_timeout_ms = static_cast<std::uint64_t>(std::stoull(sto)); } catch (...) {}
  }

  sp.allowed_mime = query_string_list("SELECT value FROM policy_lists WHERE list_type = 'allowed_mime' ORDER BY value");
  sp.allowed_extensions = query_string_list(
      "SELECT value FROM policy_lists WHERE list_type = 'allowed_extension' ORDER BY value");
  return sp;
}

bool PolicyStore::save_scan_policy(const ScanPolicy& sp) {
  if (!conn_) return false;

  std::ostringstream sql;
  sql << "BEGIN;";

  // Upsert policy_config
  sql << "INSERT INTO policy_config (id, policy_mode, suspicious_action, "
         "scan_upload, scan_download, max_scan_file_size, scan_timeout_ms) VALUES (1, "
      << escape_literal(conn_, sp.fail_open ? "fail-open" : "fail-close") << ", "
      << escape_literal(conn_, sp.block_suspicious ? "block" : "log") << ", "
      << (sp.scan_upload ? "true" : "false") << ", "
      << (sp.scan_download ? "true" : "false") << ", "
      << sp.max_scan_file_size << ", "
      << sp.scan_timeout_ms << ") "
         "ON CONFLICT (id) DO UPDATE SET "
         "policy_mode = EXCLUDED.policy_mode, "
         "suspicious_action = EXCLUDED.suspicious_action, "
         "scan_upload = EXCLUDED.scan_upload, "
         "scan_download = EXCLUDED.scan_download, "
         "max_scan_file_size = EXCLUDED.max_scan_file_size, "
         "scan_timeout_ms = EXCLUDED.scan_timeout_ms;";

  // Replace allowed_mime and allowed_extension lists
  sql << "DELETE FROM policy_lists WHERE list_type IN ('allowed_mime','allowed_extension');";
  for (const auto& v : sp.allowed_mime) {
    sql << "INSERT INTO policy_lists (list_type, value) VALUES ('allowed_mime', "
        << escape_literal(conn_, v) << ") ON CONFLICT DO NOTHING;";
  }
  for (const auto& v : sp.allowed_extensions) {
    sql << "INSERT INTO policy_lists (list_type, value) VALUES ('allowed_extension', "
        << escape_literal(conn_, v) << ") ON CONFLICT DO NOTHING;";
  }
  sql << "COMMIT;";

  return exec_simple(sql.str());
}

PolicyConfig PolicyStore::load_policy() {
  PolicyConfig p;
  if (!conn_) return p;

  // Load scan/global policy fields
  auto sp = load_scan_policy();
  p.fail_open = sp.fail_open;
  p.block_suspicious = sp.block_suspicious;

  // Load the 8 access policy lists
  static const char* list_types[] = {
      "domain_whitelist", "domain_blacklist", "user_whitelist", "user_blacklist",
      "url_whitelist", "url_blacklist", "url_category_whitelist", "url_category_blacklist",
  };
  std::vector<std::string>* fields[] = {
      &p.domain_whitelist, &p.domain_blacklist, &p.user_whitelist, &p.user_blacklist,
      &p.url_whitelist, &p.url_blacklist, &p.url_category_whitelist, &p.url_category_blacklist,
  };

  for (int i = 0; i < 8; ++i) {
    *fields[i] = query_string_list(
        std::string("SELECT value FROM policy_lists WHERE list_type = '") + list_types[i] + "' ORDER BY value");
  }

  // Load default access action
  auto daa = query_one_string("SELECT default_access_action FROM policy_config WHERE id = 1", "default_access_action");
  p.default_access_action = (daa == "block") ? AccessAction::Block : AccessAction::Allow;

  // Load access rules
  auto r = exec(conn_,
                "SELECT name, domain_whitelist, domain_blacklist, url_whitelist, url_blacklist, "
                "url_category_whitelist, url_category_blacklist, users, groups "
                "FROM access_rules ORDER BY rule_order");
  if (ok(r.get())) {
    int n = PQntuples(r.get());
    for (int i = 0; i < n; ++i) {
      AccessRule rule;
      auto name = PQgetvalue(r.get(), i, 0);
      if (name) rule.name = name;
      rule.domain_whitelist = parse_json_string_array(PQgetvalue(r.get(), i, 1));
      rule.domain_blacklist = parse_json_string_array(PQgetvalue(r.get(), i, 2));
      rule.url_whitelist = parse_json_string_array(PQgetvalue(r.get(), i, 3));
      rule.url_blacklist = parse_json_string_array(PQgetvalue(r.get(), i, 4));
      rule.url_category_whitelist = parse_json_string_array(PQgetvalue(r.get(), i, 5));
      rule.url_category_blacklist = parse_json_string_array(PQgetvalue(r.get(), i, 6));
      rule.users = parse_json_string_array(PQgetvalue(r.get(), i, 7));
      rule.groups = parse_json_string_array(PQgetvalue(r.get(), i, 8));
      p.access_rules.push_back(std::move(rule));
    }
  }

  return p;
}

bool PolicyStore::save_policy(const PolicyConfig& p) {
  if (!conn_) return false;

  std::ostringstream sql;
  sql << "BEGIN;";

  // Upsert policy_config (default_access_action + scan fields)
  sql << "INSERT INTO policy_config (id, policy_mode, suspicious_action, default_access_action, "
         "scan_upload, scan_download, max_scan_file_size, scan_timeout_ms) VALUES (1, "
      << escape_literal(conn_, p.fail_open ? "fail-open" : "fail-close") << ", "
      << escape_literal(conn_, p.block_suspicious ? "block" : "log") << ", "
      << escape_literal(conn_, to_string(p.default_access_action)) << ", "
      << "true, true, 5242880, 5000) "
         "ON CONFLICT (id) DO UPDATE SET "
         "policy_mode = EXCLUDED.policy_mode, "
         "suspicious_action = EXCLUDED.suspicious_action, "
         "default_access_action = EXCLUDED.default_access_action;";

  // Replace all 8 access policy lists
  sql << "DELETE FROM policy_lists WHERE list_type IN ("
         "'domain_whitelist','domain_blacklist','user_whitelist','user_blacklist',"
         "'url_whitelist','url_blacklist','url_category_whitelist','url_category_blacklist');";

  static const char* list_types[] = {
      "domain_whitelist", "domain_blacklist", "user_whitelist", "user_blacklist",
      "url_whitelist", "url_blacklist", "url_category_whitelist", "url_category_blacklist",
  };
  const std::vector<std::string>* fields[] = {
      &p.domain_whitelist, &p.domain_blacklist, &p.user_whitelist, &p.user_blacklist,
      &p.url_whitelist, &p.url_blacklist, &p.url_category_whitelist, &p.url_category_blacklist,
  };

  for (int i = 0; i < 8; ++i) {
    for (const auto& v : *fields[i]) {
      sql << "INSERT INTO policy_lists (list_type, value) VALUES ('" << list_types[i] << "', "
          << escape_literal(conn_, v) << ") ON CONFLICT DO NOTHING;";
    }
  }

  // Replace access rules
  sql << "DELETE FROM access_rules;";
  for (std::size_t i = 0; i < p.access_rules.size(); ++i) {
    const auto& rule = p.access_rules[i];
    sql << "INSERT INTO access_rules "
           "(rule_order, name, domain_whitelist, domain_blacklist, url_whitelist, url_blacklist, "
           "url_category_whitelist, url_category_blacklist, users, groups) VALUES ("
        << i << ", "
        << escape_literal(conn_, rule.name) << ", "
        << escape_literal(conn_, json_array(rule.domain_whitelist)) << ", "
        << escape_literal(conn_, json_array(rule.domain_blacklist)) << ", "
        << escape_literal(conn_, json_array(rule.url_whitelist)) << ", "
        << escape_literal(conn_, json_array(rule.url_blacklist)) << ", "
        << escape_literal(conn_, json_array(rule.url_category_whitelist)) << ", "
        << escape_literal(conn_, json_array(rule.url_category_blacklist)) << ", "
        << escape_literal(conn_, json_array(rule.users)) << ", "
        << escape_literal(conn_, json_array(rule.groups)) << ");";
  }

  sql << "COMMIT;";
  return exec_simple(sql.str());
}

bool PolicyStore::has_auth_config_data() {
  if (!conn_) return false;
  auto v = query_one_string("SELECT id FROM auth_config WHERE id = 1", "id");
  return !v.empty();
}

PolicyStore::AuthConfig PolicyStore::load_auth_config() {
  AuthConfig ac;
  if (!conn_) return ac;
  auto v = query_one_string("SELECT enable_proxy_auth FROM auth_config WHERE id = 1", "enable_proxy_auth");
  ac.enable_proxy_auth = (v == "t");
  auto mode = query_one_string("SELECT proxy_auth_mode FROM auth_config WHERE id = 1", "proxy_auth_mode");
  if (!mode.empty()) ac.proxy_auth_mode = mode;
  auto mitm = query_one_string("SELECT enable_https_mitm FROM auth_config WHERE id = 1", "enable_https_mitm");
  ac.enable_https_mitm = (mitm == "t");
  return ac;
}

bool PolicyStore::save_auth_config(bool enable, const std::string& mode, bool enable_mitm) {
  if (!conn_) return false;
  std::ostringstream sql;
  sql << "INSERT INTO auth_config (id, enable_proxy_auth, proxy_auth_mode, enable_https_mitm) VALUES (1, "
      << (enable ? "true" : "false") << ", "
      << escape_literal(conn_, mode) << ", "
      << (enable_mitm ? "true" : "false") << ") "
         "ON CONFLICT (id) DO UPDATE SET "
         "enable_proxy_auth = EXCLUDED.enable_proxy_auth, "
         "proxy_auth_mode = EXCLUDED.proxy_auth_mode, "
         "enable_https_mitm = EXCLUDED.enable_https_mitm";
  return exec_simple(sql.str());
}

std::vector<PolicyStore::ProxyUserRow> PolicyStore::load_proxy_users() {
  std::vector<ProxyUserRow> out;
  if (!conn_) return out;
  auto r = exec(conn_, "SELECT username, password, email, role, groups FROM proxy_users ORDER BY username");
  if (!ok(r.get())) return out;
  int n = PQntuples(r.get());
  for (int i = 0; i < n; ++i) {
    ProxyUserRow u;
    auto v = PQgetvalue(r.get(), i, 0); if (v) u.username = v;
    v = PQgetvalue(r.get(), i, 1); if (v) u.password = v;
    v = PQgetvalue(r.get(), i, 2); if (v) u.email = v;
    v = PQgetvalue(r.get(), i, 3); if (v) u.role = v;
    u.groups = parse_json_string_array(PQgetvalue(r.get(), i, 4));
    out.push_back(std::move(u));
  }
  return out;
}

bool PolicyStore::save_proxy_user(const ProxyUserRow& user) {
  if (!conn_ || user.username.empty() || user.password.empty()) return false;
  std::ostringstream sql;
  sql << "INSERT INTO proxy_users (username, password, email, role, groups) VALUES ("
      << escape_literal(conn_, user.username) << ", "
      << escape_literal(conn_, user.password) << ", "
      << escape_literal(conn_, user.email) << ", "
      << escape_literal(conn_, user.role) << ", "
      << escape_literal(conn_, json_array(user.groups)) << ") "
         "ON CONFLICT (username) DO UPDATE SET "
         "password = EXCLUDED.password, "
         "email = EXCLUDED.email, "
         "role = EXCLUDED.role, "
         "groups = EXCLUDED.groups";
  return exec_simple(sql.str());
}

bool PolicyStore::delete_proxy_user(const std::string& username) {
  if (!conn_ || username.empty()) return false;
  return exec_simple(
      std::string("DELETE FROM proxy_users WHERE username = ") + escape_literal(conn_, username));
}

bool PolicyStore::has_any_admin_user() {
  if (!conn_) return false;
  auto v = query_one_string("SELECT username FROM proxy_users WHERE role IN ('administrator','operator') LIMIT 1", "username");
  return !v.empty();
}

}  // namespace openscanproxy::policy
