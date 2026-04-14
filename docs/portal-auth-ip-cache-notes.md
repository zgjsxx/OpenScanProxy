# Portal 认证与客户端 IP 兜底排查记录

## 背景

为了解决 portal 认证下这类请求无法执行交互式 `302` 跳转的问题：

- `CORS`
- `no-cors`
- `script`
- `style`
- `image`
- 其他非顶层导航资源请求

系统增加了一条临时兜底路径：

- 顶层导航请求：继续走 portal 登录页跳转
- 非导航请求：不跳 portal，而是尝试使用“客户端 IP 登录态”直接放行

也就是：

1. 用户先完成一次 portal 登录
2. portal 登录成功后，在运行时记录 `client_ip -> username`
3. 后续非导航请求如果没有目标域认证 cookie，就查这个客户端 IP 认证缓存
4. 命中则放行，未命中则拒绝

## 现象

在实际测试中，portal 登录已经成功，但页面仍然出现大量 `403`，主要集中在：

- `script`
- `style`
- `image`
- `cors`
- `no-cors`

典型日志如下：

```text
[INFO] auth portal diagnostic: login success user=proxy client_addr=192.168.17.131:53984 client_ip=192.168.17.131 ttl_sec=3600
[WARN] proxy auth diagnostic: client-ip miss scheme=https host=assets.msn.cn client_addr=192.168.17.1:9094 client_ip=192.168.17.1 ...
```

## 根因

根因已经确认：

- portal 服务看到的“客户端 IP”是 `192.168.17.131`
- proxy 处理普通网页请求时看到的“客户端 IP”是 `192.168.17.1`

这两个地址不是同一个来源，所以按客户端 IP 做 portal 登录态兜底时必然无法命中。

### 为什么会出现两个不同地址

因为 portal 请求本身也经过了 OpenScanProxy。

实际链路不是：

```text
Browser -> Auth Portal
```

而是：

```text
Browser -> OpenScanProxy -> Auth Portal
```

因此：

- Proxy 看到的来源地址：浏览器真实地址
- Auth Portal 看到的来源地址：OpenScanProxy 自己的地址

在本次环境中对应为：

- 浏览器真实来源：`192.168.17.1`
- proxy 虚拟机地址：`192.168.17.131`

这解释了为什么 portal 登录明明成功了，但非导航请求依然持续 `client-ip miss`。

## 结论

当前“按客户端 IP 做 portal 非导航请求兜底”的方案只有在以下前提成立时才可靠：

- 浏览器访问 portal 时必须绕过代理
- Auth Portal 必须直接看到浏览器真实源地址

如果 portal 请求本身也经过代理，那么：

- portal 记录下来的地址不是真实客户端地址
- proxy 侧再拿真实客户端地址去查缓存时必然 miss

## 当前验证结论

这次排查已经确认：

- 代码本身的登录写入与查询逻辑是通的
- 问题不在 TTL，也不在是否写缓存
- 问题在于 portal 和 proxy 看到的客户端地址不一致

换句话说，最初的大量 `403` 不是策略拦截，而是认证兜底命中失败。

## 当前可行做法

如果继续保留“客户端 IP 兜底”这条路径，需要满足下面的部署条件：

- portal 地址应当绕过显式代理
- 浏览器访问 portal 时必须直连 auth 服务
- 只有这样，portal 记录下来的 `client_ip` 才能与 proxy 看到的真实客户端地址一致

## 后续建议

### 短期

继续把客户端 IP 方案作为临时兼容路径，但要明确约束：

- 仅在 portal 地址被浏览器直连时成立
- 不适合作为强依赖、通用、跨网络环境的最终认证机制

### 长期

更稳妥的方向仍然是引入“代理级全局登录态”，不要依赖源 IP。

需要说明的是，`proxy-global session token` 不一定意味着必须安装客户端软件。

它是否需要客户端软件，取决于凭据如何下发与如何随请求带回：

- 如果要让浏览器对任意站点、任意请求稳定带回一个代理专用凭据，通常需要更强的客户端控制能力
  - 例如浏览器扩展
  - 本地代理助手
  - 系统代理客户端
- 如果只依赖普通网页 cookie，而不安装客户端软件，那么这个 cookie 一般只能绑定某个具体站点，无法天然变成“全局代理认证凭据”

所以结论是：

- “代理级全局会话”本身不等于“必须安装客户端软件”
- 但想把它做成稳定、通用、跨站点、跨请求都可靠的浏览器方案，通常确实需要比纯网页 cookie 更强的客户端配合

## 建议保留的诊断日志

为了后续排查类似问题，建议保留以下日志：

- portal 登录成功日志
  - `auth portal diagnostic: login success ...`
- proxy 非导航请求命中客户端 IP 放行日志
  - `proxy auth diagnostic: client-ip hit ...`
- proxy 非导航请求客户端 IP miss 日志
  - `proxy auth diagnostic: client-ip miss ...`

这些日志可以快速判断：

- portal 是否真的记录了登录态
- proxy 是否在查询同一个地址
- 命中失败到底是“没写进去”还是“地址不一致”
