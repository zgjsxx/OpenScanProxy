# OpenScanProxy MVP 后续能力补齐清单

## 背景

当前 OpenScanProxy 仍处于 MVP 阶段，已经具备了基础可用能力：

- HTTP / HTTPS 显式代理
- 基础策略引擎
- Portal 认证链路
- Admin UI 基础管理能力
- TLS MITM 与叶子证书缓存
- 基础审计与日志

但距离一个更稳定、更接近企业可落地产品的版本，还需要继续补齐协议正确性、认证稳定性、运维能力和安全能力。

本文档用于记录后续建议支持的功能，并按优先级进行整理。

## P0：优先补齐

这些能力会直接影响可用性、稳定性和核心安全边界，应优先完成。

### 1. Portal 认证链路稳定性

目标：
- 减少“页面打开一半，子资源认证失败”的体验割裂
- 提高浏览器显式代理场景下的认证成功率

建议补齐：
- Bridge / 壳页认证模式
  - 顶层页面先进入代理可控中间页
  - 中间页完成 portal / token / cookie bootstrap
  - 完成后再跳回原站
- Portal 顶层导航与非导航请求更精细的判定规则
  - 继续完善 `Sec-Fetch-*`、`Accept`、`Upgrade-Insecure-Requests` 等信号判断
- 针对 HTTP / HTTPS / 混合站点的认证行为验证矩阵
- Portal 认证失败后的更明确用户提示页

### 2. HTTP 协议完整性

目标：
- 让 HTTP 层不仅“能解析”，而且“能正确代理、正确判断边界、减少歧义、避免被绕过”
- 减少协议兼容性问题、request smuggling 风险和后续认证、策略、扫描误判

#### 2.1 报文边界与消息体语义

建议补齐：
- `Content-Length` 与 `Transfer-Encoding` 的完整冲突处理
  - 多个 `Content-Length` 的一致性校验
  - `Transfer-Encoding` 链合法性校验
  - 明确拒绝可疑组合，防止 request smuggling
- Chunked body 的完整支持
  - trailer 支持
  - chunk extension 兼容
  - 非法 chunk 格式严格拒绝
- 无 body 响应语义
  - `HEAD`
  - `1xx`
  - `204`
  - `304`
- close-delimited body 识别
  - 没有 `Content-Length`、也没有 chunked 时，哪些响应需要靠连接关闭判断结束
- 增量解析能力
  - 区分“报文未收全”和“报文非法”
  - 避免把半包误判成坏包

#### 2.2 Request / Response 起始行支持

建议补齐：
- request-target 四种形式的完整支持
  - origin-form：`/path?a=1`
  - absolute-form：`http://example.com/path`
  - authority-form：`example.com:443`
  - asterisk-form：`OPTIONS *`
- 状态行的健壮解析
  - reason phrase 兼容
  - 异常状态行拒绝策略
- 常见 method 的兼容性验证
  - `GET`
  - `POST`
  - `HEAD`
  - `PUT`
  - `DELETE`
  - `OPTIONS`
  - `CONNECT`
  - `PATCH`
- 未知 method 的透传策略

#### 2.3 Header 语义完整性

建议补齐：
- 重复 header 保真
  - `Set-Cookie`
  - `Warning`
  - `Via`
  - 其他允许重复出现的字段
- header 的大小写无关处理继续统一
- `header_add / header_set / header_erase` 语义继续严格化
- hop-by-hop header 规范处理
  - `Connection`
  - `Proxy-Connection`
  - `Keep-Alive`
  - `TE`
  - `Trailer`
  - `Upgrade`
- `Connection` token 中声明的逐跳字段同步剥离
- 非法 header 拒绝
  - 非法字符
  - 缺少冒号
  - 异常折行
- header 尺寸限制
  - 单 header 最大长度
  - header 总大小
  - 起始行最大长度

#### 2.4 连接复用与生命周期

建议补齐：
- `message_should_close()` 更完整
  - 不只看 `Connection: close`
  - 还要结合版本与报文边界
- HTTP/1.0 keep-alive 兼容验证
- 请求 / 响应配对后的连接状态判断
- pipelining 至少做到“明确支持”或“明确拒绝”
- 上游响应未完整时的容错和清理

#### 2.5 显式代理场景专有支持

建议补齐：
- `absolute-form` 请求的稳定支持
- `CONNECT` 的 authority-form 解析和校验
- `Proxy-Authorization` / `Proxy-Authenticate` 与普通认证头的语义分离
- 转发前 request-target 规范化
  - absolute-form 转 origin-form
- 避免把代理内部参数透传到上游
  - 例如 `__osp_auth`
- `Via` / `Forwarded` / `X-Forwarded-*` 的追加与规范化策略

#### 2.6 现代浏览器兼容相关头

建议补齐：
- `Sec-Fetch-Mode`
- `Sec-Fetch-Dest`
- `Sec-Fetch-Site`
- `Upgrade-Insecure-Requests`
- `Origin`
- `Referer`

说明：
- 这些判断不一定都要放在 parser 层
- 但至少应在 HTTP 层工具中提供稳定能力，避免认证逻辑散落在代理实现各处

#### 2.7 常见功能性协议特性

建议补齐：
- `Expect: 100-continue`
- `Range` / `206 Partial Content`
- `multipart/form-data` 辅助解析
- `Content-Encoding` 感知
  - gzip
  - deflate
  - br
- `Upgrade` / WebSocket 握手识别
- `Trailer` 头处理
- `Cache-Control` / `ETag` / `If-None-Match` 等至少能够正确透传

#### 2.8 安全与歧义防护

建议补齐：
- request smuggling 防护
  - `Content-Length` / `Transfer-Encoding`
  - 多个 `Content-Length`
  - 非法 `Transfer-Encoding` 链
- header injection 防护
- 非法换行和控制字符拒绝
- 超长报文保护
- 异常包 fail-closed 策略
- 避免因解析宽松而绕过策略或扫描

#### 2.9 测试体系覆盖要求

建议补齐：
- request parsing matrix
- response parsing matrix
- chunked 边界测试
- `Content-Length` / `Transfer-Encoding` 冲突测试
- 重复 header 保真测试
- keep-alive / close 语义测试
- `CONNECT` / absolute-form / origin-form 测试
- 非法报文拒绝测试
- Portal 导航 / 非导航判定测试
- 上游真实响应样本回归测试

#### 2.10 HTTP 协议层建议实施顺序

建议优先顺序：
1. 报文边界与 body 语义
2. header 语义与重复 header 保真
3. 连接生命周期判断
4. 代理专有 request-target / `CONNECT` 支持
5. `100-continue` / `Range` / `Upgrade`

### 3. HTTPS MITM 可靠性

目标：
- 提升 HTTPS 代理兼容性与稳定性

建议补齐：
- 更多 TLS 异常站点回退策略
  - pinning
  - 协议不兼容
  - 某些站点证书校验特殊行为
- 叶子证书缓存验证与清理策略
- TLS 版本 / cipher suite 兼容性测试
- Portal 自身 HTTPS 证书与普通 MITM 证书链的一致性校验

### 4. 认证状态持久化完整性

目标：
- 让认证状态跨进程重启更稳定

建议补齐：
- `PortalSessionStore` 与 `PortalClientAuthStore` 的单元测试
- 启动恢复日志与失败恢复测试
- 文件损坏、字段缺失、部分条目过期时的回退验证
- Portal session / client-ip cache 的清理策略
  - 启动时清理
  - lookup 时惰性清理
  - 定期清理任务

## P1：建议尽快补齐

这些能力不会立刻阻塞 MVP 使用，但对于变成“可持续运行的产品”很重要。

### 5. 策略系统增强

目标：
- 让策略表达能力更接近真实企业控制需求

建议补齐：
- Rule 优先级与命中顺序可控
- Rule 命中解释更清晰
  - block page 展示命中规则
  - 审计日志展示命中规则和命中字段
- 更多条件维度
  - method
  - time window
  - file type
  - MIME
  - response status
- 更丰富的默认策略能力
- 策略导入导出

### 6. Admin UI 产品化

目标：
- 从“可用界面”走向“可管理界面”

建议补齐：
- 策略版本历史与回滚
- 配置修改审计
- 代理用户管理搜索 / 编辑 / 删除
- Portal / session / token / client-ip cache 可视化查看
- 访问测试结果更清晰
  - 命中规则
  - 用户身份来源
  - URL 分类
  - 最终动作

### 7. 审计与可观测性

目标：
- 让排障不再依赖大量临时日志

建议补齐：
- 结构化认证诊断日志
- Portal redirect / token / cookie / client-ip / basic fallback 全链路统一字段
- Metrics 导出
  - 请求数
  - 拦截数
  - portal redirect 数
  - token 消费数
  - cookie 命中数
  - client-ip 命中数
- 错误码分类统计
- 慢请求 / 慢上游统计

### 8. 测试体系补齐

目标：
- 降低回归风险

建议补齐：
- Portal 认证链路集成测试
- 策略匹配用例矩阵
- HTTP 协议边界测试继续扩展
- TLS MITM 相关回归测试
- 配置解析测试
- 持久化缓存恢复测试

## P2：中期增强

这些能力更偏产品成熟度和企业交付能力。

### 9. 代理与协议扩展

建议补齐：
- WebSocket `Upgrade` 支持
- `Expect: 100-continue`
- `Range` / `206 Partial Content`
- `multipart/form-data` 辅助解析
- 更完整的 hop-by-hop header 处理

### 10. 认证能力增强

建议补齐：
- 细粒度 logout
  - 仅退出 portal session
  - 同步清理所有相关 host cookie 的辅助方案
- 认证失效提示页
- 更完整的 hybrid 模式兼容
- 面向客户端软件或浏览器插件的全局认证 token 预留设计

### 11. 运维与部署能力

建议补齐：
- 容器化部署文档
- systemd / service 管理脚本
- 配置热加载或安全重载
- 备份与恢复说明
- 默认生产配置模板

### 12. 安全基线能力

建议补齐：
- 配置签名或敏感配置保护
- 更严格的输入校验
- 对外管理面访问控制增强
- 防止开放代理滥用的更多保护项
- 会话与 token 轮换机制

## 一个现实可执行的阶段计划

### 阶段 1：从 MVP 到稳定可用

优先完成：
- Portal 认证链路稳定性
- HTTP 协议层关键边界
- HTTPS MITM 基础兼容
- Portal session / client-ip cache 完整回归测试

### 阶段 2：从稳定可用到可管理

优先完成：
- Admin UI 管理能力增强
- 审计与可观测性补齐
- 策略系统增强
- 更多自动化测试

### 阶段 3：从可管理到可交付

优先完成：
- 部署与运维能力
- 安全基线
- 性能优化
- 更完整的协议支持

## 当前建议的下一批具体任务

如果只看接下来一到两个迭代，建议优先做这几项：

1. 为 portal session / client-ip cache 增加文档和验证步骤
2. 为 portal 认证链路补集成测试
3. 继续补 HTTP 协议层边界支持
4. 完善 block page、audit、admin test 的命中解释
5. 为 HTTPS MITM 增加异常站点回退策略

## 结论

当前 OpenScanProxy 已经具备 MVP 的核心闭环，但要迈向更稳定、更接近企业可落地的版本，后续应优先围绕以下四个方向持续补齐：

- Portal 认证稳定性
- 协议层正确性
- HTTPS MITM 兼容性
- 可观测性与测试体系

这四块补齐之后，再继续增强策略系统和 Admin UI，整体产品形态会清晰很多。
