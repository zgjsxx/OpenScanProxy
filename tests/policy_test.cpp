#include "openscanproxy/policy/policy.hpp"

#include <iostream>
#include <cstdio>
#include <fstream>
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
         expect(openscanproxy::policy::classify_url("mbd.baidu.com", "/s?q=proxy") == "search", "classify search") &&
         expect(openscanproxy::policy::classify_url("www.1688.com", "/") == "shopping", "classify shopping") &&
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

bool test_domain_category_dataset() {
  const std::string path = "./build/test_domain_categories.csv";
  {
    std::ofstream ofs(path, std::ios::trunc);
    ofs << "example.org,news\n";
    ofs << "shop.example.net,shopping\n";
  }

  const bool loaded = openscanproxy::policy::load_domain_categories_from_csv(path);
  auto c1 = openscanproxy::policy::classify_url("www.example.org", "/article/1");
  auto c2 = openscanproxy::policy::classify_url("shop.example.net", "/item/2");
  auto c3 = openscanproxy::policy::classify_url("cdn.shop.example.net", "/asset.js");

  std::remove(path.c_str());
  return expect(loaded, "load domain category csv") && expect(c1 == "news", "classify by parent domain") &&
         expect(c2 == "shopping", "classify by exact domain") && expect(c3 == "shopping", "classify by subdomain suffix");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_url_classification() && ok;
  ok = test_category_blacklist() && ok;
  ok = test_category_whitelist() && ok;
  ok = test_domain_category_dataset() && ok;
  if (ok) {
    std::cout << "All policy tests passed\n";
    return 0;
  }
  return 1;
}
