# OpenScanProxy

OpenScanProxy 是一个面向安全网关场景的开源 C++ MVP 项目：它实现了基础正向代理、文件提取、扫描引擎抽象、策略执行、审计日志和管理后台。

> 目标：先跑通可持续演进的工程骨架，而不是一次性堆砌复杂框架。

## 核心功能

- HTTP 正向代理（基础转发）
- HTTPS CONNECT 隧道（支持基础 MITM：按域名签发叶子证书并转发）
- 文件识别与提取（上传/下载，完整缓冲模式）
- 扫描器抽象接口（已实现 MockScanner + ClamAVScanner）
- 策略执行（clean/infected/suspicious/error）
- JSONL 审计日志
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

## 后续规划

- 完整 TLS MITM：动态叶子证书签发 + 缓存 + 解密 HTTP 检查
- 更完整 HTTP 解析（chunked、keep-alive）
- 多扫描引擎并行/级联
- 策略规则 DSL
- 更强会话与审计检索能力
