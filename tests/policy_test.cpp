#include "openscanproxy/policy/policy.hpp"

#include <iostream>
#include <string>

using openscanproxy::policy::AccessAction;
using openscanproxy::policy::PolicyConfig;
using openscanproxy::policy::PolicyEngine;

namespace {

bool expect(bool v, const std::string& msg) {
  if (!v) std::cerr << "FAIL: " << msg << "\n";
  return v;
}

bool test_url_classification() {
  return expect(openscanproxy::policy::classify_url("www.youtube.com", "/watch?v=1") == "video", "classify video") &&
         expect(openscanproxy::policy::classify_url("api.github.com", "/repos") == "developer", "classify developer") &&
         expect(openscanproxy::policy::classify_url("example.com", "/docs") == "other", "classify other");
}

bool test_category_blacklist() {
  PolicyConfig cfg;
  cfg.default_access_action = AccessAction::Allow;
  cfg.url_category_blacklist = {"adult", "gambling"};
  PolicyEngine engine(cfg);
  auto r = engine.evaluate_access("casino.example.com", "/promotions", "GET");
  return expect(r.action == AccessAction::Block, "category blacklist block") &&
         expect(r.matched_type == "url_category_blacklist", "category blacklist source") &&
         expect(r.url_category == "gambling", "category value");
}

bool test_category_whitelist() {
  PolicyConfig cfg;
  cfg.default_access_action = AccessAction::Block;
  cfg.url_category_whitelist = {"developer"};
  PolicyEngine engine(cfg);
  auto r = engine.evaluate_access("github.com", "/openai", "GET");
  return expect(r.action == AccessAction::Allow, "category whitelist allow") &&
         expect(r.matched_type == "url_category_whitelist", "category whitelist source") &&
         expect(r.url_category == "developer", "category value");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_url_classification() && ok;
  ok = test_category_blacklist() && ok;
  ok = test_category_whitelist() && ok;
  if (ok) {
    std::cout << "All policy tests passed\n";
    return 0;
  }
  return 1;
}
