# 集成测试

## 概述

`integration_test` 是本项目的代理级集成测试目标。

它的目标不是对单个解析器或策略函数做单元测试，而是验证代理请求的主流程端到端正确性：

- 客户端通过真实 TCP socket 连接到代理
- 代理解析请求并执行认证/策略逻辑
- 代理将流量转发到 Mock 上游服务器
- 测试同时验证代理返回的响应和上游服务器实际收到的请求

这使得 `integration_test` 介于单元测试和完整浏览器手动验证之间。

## 测试模型

当前 `tests/integration_test.cpp` 使用轻量级进程内测试框架：

- `MockUpstreamServer`
  - 启动本地环回 TCP 服务器
  - 接收代理转发过来的请求
  - 记录原始上游请求用于断言
  - 返回固定的 HTTP 响应
- `Runtime`
  - 构建与真实代理相同的运行时对象
  - 包含代理认证、策略、扫描器、审计、统计及相关配置
- `ProxyServer`
  - 由测试在后台线程中启动
  - 监听动态分配的环回端口
  - 通过正常的 socket 代码路径处理真实代理流量
- 测试客户端代码
  - 打开真实 socket 连接到代理
  - 发送原始 HTTP 或 CONNECT 请求
  - 读取原始响应
  - 解析并断言预期行为

这就是为什么集成测试比单元测试更接近真实使用场景：

- 使用真实 socket
- 执行实际的 `ProxyServer` 请求处理路径
- 验证上游转发行为，而非仅检查本地返回值

同时，它仍然比完整端到端浏览器测试更轻量：

- 不启动浏览器
- 不通过 `main.cpp` 启动完整的 `openscanproxy` 可执行文件
- 使用本地 Mock 上游而非真实互联网站点

## 当前覆盖范围

当前实现中，`integration_test` 覆盖以下代理级场景：

1. `test_http_get_forward`
   - 通过代理发送普通 HTTP `GET` 请求
   - 验证代理返回 `200`
   - 验证上游服务器收到原始格式 URI（如 `/test`）
   - 验证代理专用头部不会泄露到上游

2. `test_http_post_chunked_with_trailer`
   - 发送带 trailer 的 chunked HTTP `POST` 请求
   - 验证代理转发预期的解码 body 内容
   - 验证转发后的 trailer 内容在上游解析的请求中仍然可观测

3. `test_basic_auth_valid`
   - 启用 `basic` 模式代理认证
   - 发送有效的 `Proxy-Authorization: Basic ...`
   - 验证请求被允许并成功代理

4. `test_basic_auth_missing`
   - 启用 `basic` 模式代理认证
   - 不发送凭据
   - 验证代理返回 `407 Proxy Authentication Required`

5. `test_portal_cookie_valid`
   - 启用 `portal` 模式代理认证
   - 注入有效的域级认证 Cookie
   - 验证请求被接受而不重定向

6. `test_portal_redirect_for_browser_navigation`
   - 启用 `portal` 模式代理认证
   - 发送浏览器风格的顶层导航请求
   - 验证代理返回 `302`
   - 验证 `Location` 指向 Portal 登录端点

7. `test_portal_script_request_is_rejected_not_redirected`
   - 启用 `portal` 模式代理认证
   - 使用 `Sec-Fetch-*` 发送非导航子资源请求
   - 验证代理直接拒绝而非返回 `302` 重定向

8. `test_domain_blacklist_blocks_after_auth`
   - 启用有效的 Basic 认证
   - 安装域名黑名单策略
   - 验证认证成功后策略拦截仍然生效

9. `test_domain_whitelist_allows_when_default_block`
   - 安装默认阻止策略并设置显式白名单
   - 验证白名单域名仍能通过代理

10. `test_connect_tunnel_without_mitm`
    - 发送原始 `CONNECT` 请求
    - 验证代理返回 `200 Connection Established`
    - 在代理级验证非 MITM HTTPS 隧道路径

11. `test_connect_requires_basic_auth`
    - 启用 `basic` 模式代理认证
    - 不带凭据发送 `CONNECT`
    - 验证代理返回 `407`

## 此测试擅长的场景

此测试目标特别擅长捕获多子系统交互的回归问题：

- 请求解析 + 代理转发
- 代理认证 + 策略评估
- Portal 认证路由 + 请求分类
- CONNECT 处理 + 认证执行
- 真实代理路径中的 chunked/trailer 请求处理

换言之，它旨在回答以下问题：

- "真实代理路径是否仍然正确转发 URI 到上游？"
- "Portal 认证是否意外开始重定向子资源请求？"
- "有效的 Basic 认证请求是否仍然能通过完整代理流程？"
- "认证成功后策略是否仍然执行拦截？"

## 未覆盖的场景

`integration_test` 不是完整的浏览器或部署测试。

当前**不**验证：

- 浏览器 Cookie 存储行为
- 浏览器中 JavaScript 驱动的 Portal 流程
- 浏览器引擎执行的 CORS 行为
- HTTPS MITM 握手细节
- Portal 登录页面渲染
- `main.cpp` 启动连接和进程级启动行为
- 性能、并发压力或长期稳定性

这些仍需要：

- 低层协议逻辑的单元测试
- Portal 和页面加载行为的浏览器手动验证
- 未来可选的进程级或浏览器驱动端到端测试

## 为什么当前仅支持 POSIX

当前代理级集成测试依赖 POSIX socket 头文件和 API，包括：

- `arpa/inet.h`
- `netinet/in.h`
- `sys/socket.h`
- `unistd.h`

因此，`integration_test` 目标在 `CMakeLists.txt` 中仅对非 MSVC 平台构建。

在 Windows 上，单元测试仍可构建和运行，但此特定目标被有意排除。

## 运行方法

构建全部并启用测试：

```bash
./build.sh --tests
```

构建并立即运行所有注册测试：

```bash
./build.sh --tests --run-tests
```

直接运行集成测试目标：

```bash
./build/integration_test
```

列出 CTest 注册的测试：

```bash
./test.sh --list
```

通过 CTest 仅运行集成测试：

```bash
./test.sh --regex integration_test
```

## 诊断失败

当 `integration_test` 失败时，失败信息通常能告诉你哪个层发生了回归：

- 响应状态码不匹配
  - 认证逻辑、策略逻辑或上游转发可能发生了变更
- 上游请求解析失败
  - 代理转发格式可能回归
- 非预期的 `Location`
  - Portal 重定向分类可能变更
- `CONNECT` 上缺少 `407`
  - 隧道处理中的 Basic 认证执行可能变更

对比以下内容通常有助于定位：

- 测试客户端观察到的原始代理响应
- `MockUpstreamServer` 记录的原始请求
- `ProxyServer` 输出的应用日志

## 与单元测试的关系

本仓库仍需要两个测试层：

- 单元测试
  - 验证隔离的协议和策略行为
  - 更快且更容易定位失败
- 集成测试
  - 验证模块组合时真实代理路径仍然正常工作

两者互不替代。

## 未来改进

此集成测试套件的后续改进方向：

- 添加更清晰的逐场景 `RUN/PASS/FAIL` 控制台输出
- 扩展 Portal 令牌和 Cookie 引导覆盖范围
- 增加拦截页面内容断言以验证匹配规则可见性
- 覆盖更多上游响应边缘情况
- 在框架就绪时添加专门的 HTTPS MITM 集成覆盖