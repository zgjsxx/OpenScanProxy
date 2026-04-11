# OpenScanProxy

OpenScanProxy 是一个面向安全网关场景的开源 C++ MVP 项目：它实现了基础正向代理、文件提取、扫描引擎抽象、策略执行、审计日志和管理后台。

> 目标：先跑通可持续演进的工程骨架，而不是一次性堆砌复杂框架。

## 核心功能

- HTTP 正向代理（基础转发）
- 代理身份认证（Proxy-Authorization Basic）
- HTTPS CONNECT 隧道（支持基础 MITM：按域名签发叶子证书并转发）
- 文件识别与提取（上传/下载，完整缓冲模式）
- 扫描器抽象接口（已实现 MockScanner + ClamAVScanner）
- 策略执行（clean/infected/suspicious/error）
- 访问策略支持按用户白/黑名单控制（需启用代理认证）
- JSONL 审计日志
- 审计日志记录代理用户身份（user）
- 内置管理后台（登录、仪表盘、日志页、配置页、健康检查、metrics）

## 技术选型与依赖策略

- 语言标准：C++20（兼容 C++17 风格）
- 构建系统：CMake
- 网络：POSIX Socket
- TLS：OpenSSL（唯一强依赖）
- 其他：仅使用 C++ 标准库

### 为什么没有引入大型库

为了符合“少依赖、强边界、可维护”的原则：
- 不引入 Boost/Poco/大型 Web 框架
- 管理后台后端仅提供 API + 静态资源托管，前端使用 Vue 3 + Vite 单独构建
- 配置采用 MVP 级 JSON 解析器（仅覆盖当前 schema）

## 项目结构

```
OpenScanProxy/
├── cmd/openscanproxy/main.cpp
├── include/openscanproxy/
│   ├── admin/
│   ├── audit/
│   ├── config/
│   ├── core/
│   ├── extractor/
│   ├── http/
│   ├── policy/
│   ├── proxy/
│   ├── scanner/
│   ├── stats/
│   └── tlsmitm/
├── src/
│   ├── admin/
│   ├── audit/
│   ├── config/
│   ├── core/
│   ├── extractor/
│   ├── http/
│   ├── policy/
│   ├── proxy/
│   ├── scanner/
│   ├── stats/
│   └── tlsmitm/
├── configs/config.json
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── web/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
└── CMakeLists.txt
```

## 架构概览

- **proxy**：接入流量，触发扫描流程，执行策略
- **extractor**：识别并提取候选文件
- **scanner**：标准接口 + 具体引擎实现
- **policy**：统一动作决策
- **audit**：结构化审计日志
- **admin**：管理 HTTP 服务与页面
- **stats**：运行时计数与 metrics 输出
- **tlsmitm**：MITM 引擎（CA 加载、按域名签发叶子证书、TLS 终止/转发）

## 快速开始

### 1) 构建

```bash
cmake -S . -B build
cmake --build build -j
```

### 2) 运行

```bash
./build/openscanproxy configs/config.json
```

- 代理端口：`8080`
- 管理后台：`http://127.0.0.1:9090`

### 3) 浏览器配置代理

将浏览器代理设置为：`127.0.0.1:8080`。

如需开启代理鉴权（Basic）：
- `enable_proxy_auth=true`
- `proxy_auth_user`
- `proxy_auth_password`
- `proxy_users_file`（代理用户持久化文件，默认 `./configs/proxy_users.json`）

未携带或鉴权失败将返回 `407 Proxy Authentication Required`。

你也可以在管理后台 `/policy` 页面创建代理用户；创建后会自动启用代理鉴权，客户端首次访问会收到浏览器用户名/密码弹窗。创建/更新的用户会持久化写入 `proxy_users_file`。

## 生成本地 CA（用于 HTTPS MITM）

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout certs/ca.key -out certs/ca.crt -subj "/CN=OpenScanProxy Local CA"
```

然后在 `configs/config.json` 中配置：
- `ca_cert_path`
- `ca_key_path`
- `enable_https_mitm`

## 系统/浏览器信任 CA

将 `certs/ca.crt` 导入系统或浏览器受信任根证书（不同系统命令不同）。

## ClamAV / clamd

推荐 clamd 在线扫描：

```bash
sudo apt-get install -y clamav clamav-daemon
sudo systemctl start clamav-daemon
```

配置中将 `scanner_type` 设为 `clamav`，并设置：
- Unix Socket：`clamav_mode=unix` + `clamav_unix_socket`
- TCP：`clamav_mode=tcp` + `clamav_host/clamav_port`

## 上传/下载扫描验证

- 上传：向任意 HTTP 站点发送 multipart/form-data
- 下载：访问带 `Content-Disposition: attachment` 或 `application/*` 类型响应
- MockScanner 测试：文件名含 `eicar` 或内容含 `virus` 时会命中 infected

## 管理后台功能

- 前端路由：`/login`、`/dashboard`、`/logs`、`/policy`
- API：`/api/stats`、`/api/logs`、`/api/policy`、`/api/config`
- 认证：`/api/login`、`/api/logout`（Cookie Session）
- 健康检查：`/healthz` `/readyz`
- 指标：`/metrics`

### 前端开发与发布（可复现）

1. 安装依赖：

```bash
cd web
npm install
```

2. 开发模式（Vite dev server）：

```bash
cd web
npm run dev
```

3. 生产构建（输出到 `web/dist`）：

```bash
cd web
npm run build
```

4. 启动 OpenScanProxy（生产模式读取静态资源）：

```bash
./build/openscanproxy configs/config.json
```

默认读取 `admin_static_dir`（示例值：`./web/dist`）。可在 `configs/config.json` 中修改部署目录。

## 已知限制（MVP）
- HTTPS MITM 尚未接入解密后 HTTP 级扫描（当前仅做 TLS 终止与转发）
- HTTP 解析器为简化实现，不覆盖分块传输、连接复用等完整协议边界
- 配置 JSON 解析器仅覆盖当前 schema
- 无流式扫描、无异步队列

## TODO List（下一阶段开发清单）

### P0：先补齐可用性与协议能力
- [ ] HTTPS MITM 接入解密后 HTTP 级扫描链路（请求/响应都可执行策略）
- [ ] 完善 HTTP 协议处理（chunked、keep-alive、基础连接复用）
- [ ] 扫描流程支持流式处理，减少大文件全量缓冲带来的内存压力
- [ ] 增加扫描超时、失败回退与熔断策略

### P1：补齐可商用策略能力
- [ ] 策略引擎升级为 DSL（支持 allow/block/quarantine/isolate 等动作）
- [ ] 引入多引擎编排（并行/级联扫描）
- [ ] 增加身份维度策略（按用户/用户组下发规则）
- [ ] 增加 DLP Lite（关键词/正则/文件指纹）与上传外发控制

### P2：平台化与可观测性
- [ ] 完善审计检索（多条件过滤、聚合统计、导出）
- [ ] 增加异步任务队列与重试机制
- [ ] 增加风险评分与自适应策略（基于会话/行为）
- [ ] 增加管理面配置版本化与变更审计
