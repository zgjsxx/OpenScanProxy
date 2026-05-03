# 数据库表结构

OpenScanProxy 使用 PostgreSQL 存储策略、规则、认证配置和代理用户数据。

## 表一览

| 表名 | 说明 | 行数 |
|---|---|---|
| `policy_config` | 全局策略配置（单行，id=1） | 1 |
| `policy_lists` | 全局黑白名单（域名/用户/URL/分类） | 多行 |
| `access_rules` | 自定义访问规则（按 rule_order 排序） | 多行 |
| `auth_config` | 认证与 MITM 配置（单行，id=1） | 1 |
| `proxy_users` | 代理用户（鉴权用） | 多行 |

---

## 1. policy_config — 全局策略配置

单行表，始终操作 `id = 1`。

```sql
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
```

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `policy_mode` | TEXT | `fail-open` | 扫描失败策略：`fail-open` 放行 / `fail-close` 拦截 |
| `suspicious_action` | TEXT | `log` | 可疑文件处理：`log` 记录 / `block` 拦截 |
| `default_access_action` | TEXT | `allow` | 默认访问动作：`allow` 放行 / `block` 拦截 |
| `scan_upload` | BOOLEAN | `true` | 是否扫描上传文件 |
| `scan_download` | BOOLEAN | `true` | 是否扫描下载文件 |
| `max_scan_file_size` | INTEGER | `5242880` | 最大扫描文件大小（字节） |
| `scan_timeout_ms` | INTEGER | `5000` | 扫描超时（毫秒） |

## 2. policy_lists — 全局黑白名单

每行一条名单条目，通过 `list_type` 区分类型。

```sql
CREATE TABLE IF NOT EXISTS policy_lists (
    id          SERIAL PRIMARY KEY,
    list_type   TEXT NOT NULL,
    value       TEXT NOT NULL,
    UNIQUE (list_type, value)
);

CREATE INDEX IF NOT EXISTS idx_policy_lists_type ON policy_lists (list_type);
```

`list_type` 取值：

| list_type | 对应 config.json 字段 | 说明 |
|---|---|---|
| `domain_whitelist` | `domain_whitelist` | 域名白名单 |
| `domain_blacklist` | `domain_blacklist` | 域名黑名单 |
| `user_whitelist` | `user_whitelist` | 用户白名单 |
| `user_blacklist` | `user_blacklist` | 用户黑名单 |
| `url_whitelist` | `url_whitelist` | URL 路径白名单 |
| `url_blacklist` | `url_blacklist` | URL 路径黑名单 |
| `url_category_whitelist` | `url_category_whitelist` | URL 分类白名单 |
| `url_category_blacklist` | `url_category_blacklist` | URL 分类黑名单 |
| `allowed_mime` | `allowed_mime` | 允许扫描的 MIME 类型 |
| `allowed_extensions` | `allowed_extensions` | 允许扫描的文件扩展名 |

## 3. access_rules — 自定义访问规则

按 `rule_order` 升序匹配，首次命中即生效。

```sql
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
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `rule_order` | INTEGER | 匹配优先级（越小越优先） |
| `name` | TEXT | 规则名称 |
| `domain_whitelist` | JSONB | 域名白名单数组 |
| `domain_blacklist` | JSONB | 域名黑名单数组 |
| `url_whitelist` | JSONB | URL 路径白名单数组 |
| `url_blacklist` | JSONB | URL 路径黑名单数组 |
| `url_category_whitelist` | JSONB | URL 分类白名单数组 |
| `url_category_blacklist` | JSONB | URL 分类黑名单数组 |
| `users` | JSONB | 规则生效的用户数组（空=所有用户） |
| `groups` | JSONB | 规则生效的用户组数组（空=不限） |

## 4. auth_config — 认证与 MITM 配置

单行表，始终操作 `id = 1`。

```sql
CREATE TABLE IF NOT EXISTS auth_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    enable_proxy_auth   BOOLEAN NOT NULL DEFAULT false,
    proxy_auth_mode     TEXT NOT NULL DEFAULT 'basic',
    enable_https_mitm   BOOLEAN NOT NULL DEFAULT false
);
```

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enable_proxy_auth` | BOOLEAN | `false` | 是否启用代理鉴权 |
| `proxy_auth_mode` | TEXT | `basic` | 鉴权模式：`basic` / `portal` / `other` |
| `enable_https_mitm` | BOOLEAN | `false` | 是否启用 HTTPS MITM 解密 |

## 5. proxy_users — 代理用户

```sql
CREATE TABLE IF NOT EXISTS proxy_users (
    username    TEXT PRIMARY KEY,
    password    TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'user',
    groups      JSONB NOT NULL DEFAULT '[]'
);
```

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `username` | TEXT | — | 用户名（主键） |
| `password` | TEXT | — | 密码 |
| `email` | TEXT | `''` | 邮箱地址 |
| `role` | TEXT | `user` | 角色：`user` / `operator` / `administrator` |
| `groups` | JSONB | `[]` | 所属用户组数组 |

## 数据流向

```
config.json ──(首次迁移)──▶ PostgreSQL ──(启动加载)──▶ Runtime 内存
                                ▲
Web UI ──(POST /api/*)─────────┘
```

- **首次启动**：如果数据库中无数据，从 `config.json` 迁移到 PostgreSQL
- **后续启动**：从 PostgreSQL 加载，数据库中的值覆盖 `config.json`
- **Web UI 操作**：直接写入 PostgreSQL，不回写 `config.json`
- **初始管理员**：通过环境变量 `OSPROXY_INIT_ADMIN_USER` / `OSPROXY_INIT_ADMIN_PASSWORD` 在启动时创建
