# TLS 叶子证书双层缓存

## 功能说明

OpenScanProxy 现在支持 TLS MITM 叶子证书的双层缓存：

- 进程内内存缓存：`host -> SSL_CTX`
- 磁盘缓存：`host -> cert.pem + key.pem`

目标是减少同一 host 被重复 MITM 时的叶子证书签发开销，并让服务重启后仍可复用已经生成过的 leaf cert/key。

本功能只影响 TLS MITM 证书复用路径，不改变现有 portal auth、bridge auth、policy 判定和代理转发语义。

## 命中顺序

`TLSMitmEngine::create_server_ctx_for_host(host)` 的执行顺序如下：

1. 先查进程内内存缓存
2. 内存未命中时查磁盘缓存目录
3. 磁盘也未命中时，现场签发新的 leaf cert/key
4. 新签发的 cert/key 会回写到磁盘缓存，并将构建好的 `SSL_CTX` 放入内存缓存

## 配置项

在 [configs/config.json](../configs/config.json) 中新增了两个配置项：

```json
{
  "enable_https_mitm": true,
  "tls_leaf_cache_enabled": true,
  "tls_leaf_cache_dir": "./certs/cache"
}
```

### `tls_leaf_cache_enabled`

- 类型：`bool`
- 默认值：`true`
- 作用：控制是否启用 leaf cert 内存/磁盘缓存

### `tls_leaf_cache_dir`

- 类型：`string`
- 默认值：`./certs/cache`
- 作用：指定磁盘缓存目录

如果该目录不存在，初始化阶段会尝试自动创建。

## 磁盘缓存文件格式

每个 host 会生成一对文件：

- `<safe-host>.crt.pem`
- `<safe-host>.key.pem`

当前实现中的 `<safe-host>` 是对原始 host 做十六进制编码后的结果，这样可以：

- 避免路径注入
- 兼容普通域名、IPv4、IPv6
- 避免文件名里的特殊字符影响落盘

例如，某个 host 的缓存目录中会看到类似：

```text
./certs/cache/
  7777772e62616964752e636f6d.crt.pem
  7777772e62616964752e636f6d.key.pem
```

这对应的是 `www.baidu.com`。

## 启动时预加载

在 `TLSMitmEngine::initialize(...)` 成功加载 CA 后，会同步扫描缓存目录：

- 只识别 `*.crt.pem`
- 要求同时存在同名的 `*.key.pem`
- 只有 cert/key 都能成功解析，且能成功构建 `SSL_CTX`，才会放入进程内缓存
- 损坏、不完整或不匹配的缓存项会跳过，并记录告警日志

## 日志行为

缓存路径增加了几类关键日志，便于判断命中情况：

- 内存命中：`tls leaf cache: memory hit for <host>`
- 磁盘命中：`tls leaf cache: disk hit for <host>`
- 启动预加载成功：`tls leaf cache: loaded cached leaf ctx <safe-host>`
- 磁盘加载失败：`tls leaf cache: disk load failed for <host>`
- 新签发：`tls leaf cache: issued new leaf ctx for <host>`
- 持久化失败：`tls leaf cache: failed to persist leaf material for <host>`

## 如何验证

下面给你一套建议的验证顺序，按这套跑最容易看出效果。

### 1. 准备条件

先确认：

- `enable_https_mitm=true`
- `tls_leaf_cache_enabled=true`
- `tls_leaf_cache_dir` 指向一个你方便观察的目录
- CA 已正确生成并被浏览器/系统信任

建议测试前先清空缓存目录，避免历史数据干扰。

### 2. 首次签发验证

目标：确认第一次访问某个 HTTPS host 时，会即时签发并写入磁盘。

操作：

1. 清空 `tls_leaf_cache_dir`
2. 启动 OpenScanProxy
3. 通过代理访问一个此前未访问过的 HTTPS 站点，例如 `https://www.baidu.com`

期望结果：

- 代理日志出现 `issued new leaf ctx for www.baidu.com`
- `tls_leaf_cache_dir` 下出现一对新的 `.crt.pem` / `.key.pem` 文件
- 页面能正常完成 TLS MITM 流程

### 3. 同进程内存命中验证

目标：确认同一进程内再次访问相同 host 时，不会重复签发。

操作：

1. 保持 OpenScanProxy 进程不重启
2. 再次访问同一个 HTTPS host

期望结果：

- 代理日志出现 `memory hit for www.baidu.com`
- 不再出现新的 `issued new leaf ctx for www.baidu.com`
- 磁盘目录中文件数量不增加

### 4. 重启后磁盘恢复验证

目标：确认服务重启后会从磁盘恢复，而不是重新签发。

操作：

1. 保留 `tls_leaf_cache_dir` 中已生成的缓存文件
2. 重启 OpenScanProxy
3. 再次访问同一个 HTTPS host

期望结果：

- 启动阶段日志可能出现 `loaded cached leaf ctx <safe-host>`
- 首次访问该 host 时出现 `memory hit` 或 `disk hit`
- 不应再次出现 `issued new leaf ctx for www.baidu.com`

说明：

- 如果启动时已经预加载进内存，那么访问时通常会直接看到 `memory hit`
- 如果未来改成懒加载模式，则可能先看到 `disk hit`

### 5. 多 host 验证

目标：确认不同 host 会各自独立缓存。

操作：

1. 依次访问多个不同 HTTPS host
2. 例如：
   `https://www.baidu.com`
   `https://www.163.com`
   `https://www.bing.com`

期望结果：

- 每个 host 第一次访问都会各自产生一对缓存文件
- 日志里能看到对应 host 的单独签发或命中记录

### 6. SAN 正确性验证

目标：确认域名与 IP 的 SAN 类型正确。

操作：

1. 访问一个基于域名的 HTTPS 站点
2. 如果你的测试环境允许，再访问一个用 IP 直连的 HTTPS 目标
3. 用 `openssl x509 -in <crt.pem> -text -noout` 查看缓存下的 leaf cert

期望结果：

- 域名 host 的 SAN 中包含 `DNS:<host>`
- IP host 的 SAN 中包含 `IP Address:<ip>`

### 7. 异常回退验证

目标：确认缓存损坏不会阻断主流程。

操作：

1. 手动删除某个 host 的 `.key.pem` 或写坏 `.crt.pem`
2. 重启 OpenScanProxy 或重新访问该 host

期望结果：

- 日志出现类似 `failed to load cached cert/key pair` 或 `disk load failed`
- 代理会自动重新签发新的 leaf cert
- 新的 cert/key 会重新写回磁盘

## 推荐验证命令

如果你想直接看缓存目录变化，可以用：

```powershell
Get-ChildItem ./certs/cache
```

如果你想检查某张缓存证书内容，可以用：

```powershell
openssl x509 -in .\certs\cache\<safe-host>.crt.pem -text -noout
```

如果你想重点关注日志里的缓存行为，可以搜索：

```text
tls leaf cache:
```

## 注意事项

- 当前缓存不做淘汰策略
- 当前缓存不做证书轮换和过期清理
- 当前缓存文件格式没有单独版本号
- 当前预加载日志里的 host 标识是 `safe-host` 文件名，不是原始 host 文本
- `SSL_CTX` 返回给调用方时做了引用计数增加，以保证缓存持有和调用方释放不会互相冲突

## 适用范围

该缓存主要影响：

- 普通 HTTPS MITM 目标站点
- 使用 TLS 证书的 portal 监听场景

只要最终 leaf cert 是通过 `TLSMitmEngine::create_server_ctx_for_host(...)` 构建出来的，就会走这套缓存逻辑。
