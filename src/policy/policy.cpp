#include "openscanproxy/policy/policy.hpp"

#include "openscanproxy/core/util.hpp"

#include <fstream>
#include <unordered_map>

namespace openscanproxy::policy {
namespace {

std::mutex g_category_mu;
std::unordered_map<std::string, std::string> g_domain_categories;

bool wildcard_match_impl(const std::string& value, const std::string& pattern, std::size_t vi, std::size_t pi) {
  if (pi == pattern.size()) return vi == value.size();
  if (pattern[pi] == '*') {
    for (std::size_t i = vi; i <= value.size(); ++i) {
      if (wildcard_match_impl(value, pattern, i, pi + 1)) return true;
    }
    return false;
  }
  if (vi < value.size() && value[vi] == pattern[pi]) return wildcard_match_impl(value, pattern, vi + 1, pi + 1);
  return false;
}

bool wildcard_match(const std::string& value, const std::string& pattern) {
  return wildcard_match_impl(value, pattern, 0, 0);
}

bool match_rule(const std::string& value, const std::string& rule) {
  if (rule.empty()) return false;
  if (value == rule) return true;
  if (rule.find('*') != std::string::npos) return wildcard_match(value, rule);
  if (rule.back() == '/') return value.rfind(rule, 0) == 0;
  return false;
}

bool find_matched_rule(const std::vector<std::string>& rules, const std::string& value, std::string& hit) {
  for (const auto& rule : rules) {
    if (match_rule(value, rule)) {
      hit = rule;
      return true;
    }
  }
  return false;
}

bool user_matches_rule(const std::vector<std::string>& users, const std::string& user_l) {
  if (users.empty()) return true;
  if (user_l.empty()) return false;
  std::string hit;
  return find_matched_rule(users, user_l, hit);
}

AccessPolicyResult evaluate_named_rule(const AccessRule& rule, const std::string& host_l, const std::string& url,
                                      const std::string& category) {
  std::string hit;
  const auto rule_name = rule.name.empty() ? "<unnamed>" : rule.name;
  if (find_matched_rule(rule.domain_whitelist, host_l, hit)) {
    return {AccessAction::Allow, rule_name + ":domain_whitelist:" + hit, "rule_domain_whitelist",
            "matched rule domain whitelist", category};
  }
  if (find_matched_rule(rule.url_whitelist, url, hit)) {
    return {AccessAction::Allow, rule_name + ":url_whitelist:" + hit, "rule_url_whitelist",
            "matched rule url whitelist", category};
  }
  if (find_matched_rule(rule.url_category_whitelist, category, hit)) {
    return {AccessAction::Allow, rule_name + ":url_category_whitelist:" + hit, "rule_url_category_whitelist",
            "matched rule url category whitelist", category};
  }
  if (find_matched_rule(rule.domain_blacklist, host_l, hit)) {
    return {AccessAction::Block, rule_name + ":domain_blacklist:" + hit, "rule_domain_blacklist",
            "matched rule domain blacklist", category};
  }
  if (find_matched_rule(rule.url_blacklist, url, hit)) {
    return {AccessAction::Block, rule_name + ":url_blacklist:" + hit, "rule_url_blacklist",
            "matched rule url blacklist", category};
  }
  if (find_matched_rule(rule.url_category_blacklist, category, hit)) {
    return {AccessAction::Block, rule_name + ":url_category_blacklist:" + hit, "rule_url_category_blacklist",
            "matched rule url category blacklist", category};
  }
  return {AccessAction::Allow, "", "", "", category};
}

bool contains_any(const std::string& text, const std::vector<std::string>& needles) {
  for (const auto& n : needles) {
    if (!n.empty() && text.find(n) != std::string::npos) return true;
  }
  return false;
}

std::string classify_by_domain_data(const std::string& host_l) {
  if (host_l.empty()) return "";
  std::lock_guard<std::mutex> lk(g_category_mu);
  auto exact = g_domain_categories.find(host_l);
  if (exact != g_domain_categories.end()) return exact->second;

  auto dot = host_l.find('.');
  while (dot != std::string::npos) {
    auto suffix = host_l.substr(dot + 1);
    auto it = g_domain_categories.find(suffix);
    if (it != g_domain_categories.end()) return it->second;
    dot = host_l.find('.', dot + 1);
  }
  return "";
}

}  // namespace

bool load_domain_categories_from_csv(const std::string& path) {
  std::ifstream ifs(path);
  if (!ifs) return false;

  std::unordered_map<std::string, std::string> loaded;
  std::string line;
  while (std::getline(ifs, line)) {
    auto text = core::trim(line);
    if (text.empty() || text[0] == '#') continue;
    auto comma = text.find(',');
    if (comma == std::string::npos) continue;
    auto domain = core::to_lower(core::trim(text.substr(0, comma)));
    auto category = core::to_lower(core::trim(text.substr(comma + 1)));
    if (domain.empty() || category.empty()) continue;
    loaded[domain] = category;
  }

  std::lock_guard<std::mutex> lk(g_category_mu);
  g_domain_categories = std::move(loaded);
  return true;
}

std::string classify_url(const std::string& host, const std::string& url) {
  const auto host_l = core::to_lower(host);
  const auto url_l = core::to_lower(url);
  const auto text = host_l + " " + url_l;

  if (auto domain_category = classify_by_domain_data(host_l); !domain_category.empty()) return domain_category;

  if (contains_any(text, {"porn", "adult", "sex", "xvideos", "xnxx", "onlyfans"})) return "adult";
  if (contains_any(text, {"casino", "bet", "gambl", "poker", "lottery", "slot"})) return "gambling";
  if (contains_any(text, {"facebook", "twitter", "x.com", "instagram", "tiktok", "weibo", "reddit"})) return "social";
  if (contains_any(text, {"youtube", "netflix", "bilibili", "twitch", "spotify", "douyin", "youku", "iqiyi", "qq.com/video"})) return "video";
  if (contains_any(text, {"github", "gitlab", "bitbucket", "npmjs", "pypi", "docker"})) return "developer";
  if (contains_any(text, {"game", "steam", "epicgames", "riotgames", "roblox", "minecraft"})) return "game";
  if (contains_any(text, {"drive.google.com", "dropbox", "onedrive", "box.com", "mega.nz", "aliyundrive"})) return "cloud_storage";
  if (contains_any(text, {"amazon", "taobao", "tmall", "ebay", "jd.com", "shop", "1688", "alicdn", "alibaba"})) return "shopping";
  if (contains_any(text, {"bank", "pay", "wallet", "finance", "alipay", "paypal", "tenpay"})) return "finance";
  if (contains_any(text, {"news", "cnn", "bbc", "reuters", "nytimes", "toutiao", "thepaper"})) return "news";
  if (contains_any(text, {"baidu", "bing", "google", "sogou", "so.com", "duckduckgo"})) return "search";
  return "other";
}

core::Action PolicyEngine::decide(const core::ScanResult& result) const {
  auto cfg = config();
  switch (result.status) {
    case core::ScanStatus::Clean:
      return core::Action::Allow;
    case core::ScanStatus::Infected:
      return core::Action::Block;
    case core::ScanStatus::Suspicious:
      return cfg.block_suspicious ? core::Action::Block : core::Action::LogOnly;
    case core::ScanStatus::Error:
      return cfg.fail_open ? core::Action::Allow : core::Action::Block;
  }
  return core::Action::Block;
}

AccessPolicyResult PolicyEngine::evaluate_access(const std::string& host, const std::string& url,
                                                 const std::string& /*method*/, const std::string& user) const {
  auto cfg = config();
  const auto host_l = core::to_lower(host);
  const auto user_l = core::to_lower(user);
  const auto category = classify_url(host, url);
  std::string hit;

  if (!user_l.empty() && find_matched_rule(cfg.user_whitelist, user_l, hit)) {
    return {AccessAction::Allow, hit, "user_whitelist", "matched user whitelist", category};
  }
  if (!user_l.empty() && find_matched_rule(cfg.user_blacklist, user_l, hit)) {
    return {AccessAction::Block, hit, "user_blacklist", "matched user blacklist", category};
  }
  if (find_matched_rule(cfg.domain_whitelist, host_l, hit)) {
    return {AccessAction::Allow, hit, "domain_whitelist", "matched domain whitelist", category};
  }
  if (find_matched_rule(cfg.url_whitelist, url, hit)) {
    return {AccessAction::Allow, hit, "url_whitelist", "matched url whitelist", category};
  }
  if (find_matched_rule(cfg.url_category_whitelist, category, hit)) {
    return {AccessAction::Allow, hit, "url_category_whitelist", "matched url category whitelist", category};
  }
  if (find_matched_rule(cfg.domain_blacklist, host_l, hit)) {
    return {AccessAction::Block, hit, "domain_blacklist", "matched domain blacklist", category};
  }
  if (find_matched_rule(cfg.url_blacklist, url, hit)) {
    return {AccessAction::Block, hit, "url_blacklist", "matched url blacklist", category};
  }
  if (find_matched_rule(cfg.url_category_blacklist, category, hit)) {
    return {AccessAction::Block, hit, "url_category_blacklist", "matched url category blacklist", category};
  }
  for (const auto& rule : cfg.access_rules) {
    if (!user_matches_rule(rule.users, user_l)) continue;
    auto result = evaluate_named_rule(rule, host_l, url, category);
    if (!result.matched_type.empty()) return result;
  }
  return {cfg.default_access_action, "", "default_access_action", "fallback to default access action", category};
}

PolicyConfig PolicyEngine::config() const {
  std::lock_guard<std::mutex> lk(mu_);
  return cfg_;
}

void PolicyEngine::update(PolicyConfig cfg) {
  std::lock_guard<std::mutex> lk(mu_);
  cfg_ = cfg;
}

std::string to_string(core::ScanStatus status) {
  switch (status) {
    case core::ScanStatus::Clean: return "clean";
    case core::ScanStatus::Infected: return "infected";
    case core::ScanStatus::Suspicious: return "suspicious";
    case core::ScanStatus::Error: return "error";
  }
  return "error";
}

std::string to_string(core::Action action) {
  switch (action) {
    case core::Action::Allow: return "allow";
    case core::Action::Block: return "block";
    case core::Action::LogOnly: return "log";
  }
  return "block";
}

std::string to_string(AccessAction action) {
  switch (action) {
    case AccessAction::Allow: return "allow";
    case AccessAction::Block: return "block";
  }
  return "allow";
}

AccessAction access_action_from_string(const std::string& action) {
  return core::to_lower(action) == "block" ? AccessAction::Block : AccessAction::Allow;
}

}  // namespace openscanproxy::policy
