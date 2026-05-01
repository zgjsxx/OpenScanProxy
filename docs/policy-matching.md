# 策略匹配规则

## 评估顺序

`PolicyEngine::evaluate_access()` (`src/policy/policy.cpp:169`) 按以下优先级逐级匹配：

### 1. 全局白名单（任意命中 → Allow，短路返回）

| 检查项 | 匹配对象 |
|---|---|
| `user_whitelist` | 请求用户 |
| `domain_whitelist` | 请求域名（小写） |
| `url_whitelist` | 请求 URL 路径 |
| `url_category_whitelist` | 域名分类（CSV 数据） |

### 2. 全局黑名单（任意命中 → Block，短路返回）

| 检查项 | 匹配对象 |
|---|---|
| `user_blacklist` | 请求用户 |
| `domain_blacklist` | 请求域名（小写） |
| `url_blacklist` | 请求 URL 路径 |
| `url_category_blacklist` | 域名分类（CSV 数据） |

### 3. 命中规则（access_rules）

逐条遍历，**第一条匹配即停止**。

单条规则的匹配逻辑（`evaluate_named_rule`, `src/policy/policy.cpp:55-84`）：

```
用户匹配（AND 前提）
  └─ 条件匹配（OR 关系）：
       ├─ 域名匹配  → 命中
       ├─ URL 匹配  → 命中
       └─ 分类匹配  → 命中
```

- **用户**：`user_matches_rule()` 检查请求用户是否在规则的 `users` 列表中。`users` 为空时匹配所有用户。
- **条件**：域名、URL、分类之间是 **OR** 关系 —— 任意一项匹配即触发规则动作（allow/block）。
- **动作**：`action=allow` 时条件写入白名单字段，`action=block` 时写入黑名单字段。

> 例如：一条规则 users=test001, domain=baidu.com, category=game, action=allow
> → test001 访问 baidu.com **或** 任意 game 分类站点都会被放行。

### 4. 默认规则

以上全部未命中时，取 `default_access_action`（allow 或 block）。

## 通配符匹配

`match_rule()` (`src/policy/policy.cpp:30`) 使用 `fnmatch` 进行 glob 匹配：

- `*` 匹配任意字符序列
- `?` 匹配单个字符
- 例如白名单填 `*.company.local` 可匹配所有内网子域名

## MITM 决策

`handle_connect_tunnel()` (`src/proxy/proxy_server.cpp:810-817`)：

```
enable_https_mitm = true  → 始终 MITM
  否则 portal 认证已启用 → 仅对未认证用户 MITM
  否则 → 直接隧道转发（不解密）
```

IP 缓存（`portal_client_auth`）在 cookie/token 认证成功后更新，已认证 IP 在 MITM 内部跳过 portal 重定向，但流量仍被解密扫描。
