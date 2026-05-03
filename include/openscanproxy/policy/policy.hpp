#pragma once

#include "openscanproxy/core/types.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace openscanproxy::policy {

// 访问策略动作：允许或阻止
enum class AccessAction { Allow, Block };

// 自定义访问规则：匹配用户/域名/URL/分类，执行指定动作
struct AccessRule {
  std::string name;                        // 规则名称
  std::vector<std::string> users;          // 匹配的用户列表
  std::vector<std::string> groups;         // 匹配的用户组列表
  std::vector<std::string> domain_whitelist;  // 域名白名单
  std::vector<std::string> domain_blacklist;  // 域名黑名单
  std::vector<std::string> url_whitelist;     // URL 白名单
  std::vector<std::string> url_blacklist;     // URL 黑名单
  std::vector<std::string> url_category_whitelist; // URL 分类白名单
  std::vector<std::string> url_category_blacklist; // URL 分类黑名单
};

// 策略引擎配置
struct PolicyConfig {
  bool fail_open{true};                    // 扫描失败时是否放行（true=放行，false=阻止）
  bool block_suspicious{false};            // 是否阻止可疑文件
  std::vector<std::string> domain_whitelist;   // 全局域名白名单
  std::vector<std::string> domain_blacklist;   // 全局域名黑名单
  std::vector<std::string> user_whitelist;     // 全局用户白名单
  std::vector<std::string> user_blacklist;     // 全局用户黑名单
  std::vector<std::string> url_whitelist;      // 全局 URL 白名单
  std::vector<std::string> url_blacklist;      // 全局 URL 黑名单
  std::vector<std::string> url_category_whitelist; // 全局 URL 分类白名单
  std::vector<std::string> url_category_blacklist; // 全局 URL 分类黑名单
  std::vector<AccessRule> access_rules;    // 自定义规则列表（按顺序匹配）
  AccessAction default_access_action{AccessAction::Allow}; // 默认动作
};

// 访问策略评估结果
struct AccessPolicyResult {
  AccessAction action{AccessAction::Allow}; // 最终动作
  std::string matched_rule;                // 匹配的规则名
  std::string matched_type;                // 匹配的类型（domain/user/url/category/rule）
  std::string reason;                      // 阻止原因描述
  std::string url_category;                // URL 分类标签
};

// 访问策略引擎，根据域名/URL/用户/分类等规则决定请求是否放行
class PolicyEngine {
 public:
  explicit PolicyEngine(PolicyConfig cfg) : cfg_(cfg) {}
  // 根据扫描结果决定动作
  core::Action decide(const core::ScanResult& result) const;
  // 根请求的 host/url/method/user 评估访问策略
  AccessPolicyResult evaluate_access(const std::string& host, const std::string& url, const std::string& method,
                                     const std::string& user = "") const;
  PolicyConfig config() const;
  // 动态更新策略配置
  void update(PolicyConfig cfg);
  // 设置用户组存储（用于展开规则中的 group 引用），非 owning
  void set_user_group_provider(void* provider) { user_groups_ = provider; }

 private:
  mutable std::mutex mu_;
  PolicyConfig cfg_;
  void* user_groups_{nullptr};
};

// 枚举转字符串
std::string to_string(core::ScanStatus status);
std::string to_string(core::Action action);
std::string to_string(AccessAction action);
// 字符串转访问动作
AccessAction access_action_from_string(const std::string& action);
// 从 CSV 文件加载域名分类数据
bool load_domain_categories_from_csv(const std::string& path);
// 根据域名和 URL 判断分类标签
std::string classify_url(const std::string& host, const std::string& url);

}  // namespace openscanproxy::policy
