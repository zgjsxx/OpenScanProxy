# HTTP Chunked Trailer 介绍

## 什么是 Trailer

Trailer 是 HTTP chunked 传输编码中的一个可选部分，允许在消息体**发送完毕后**再追加额外的头部字段。

普通 HTTP 消息的头部必须在 body 之前发送，但有些信息（如内容校验值）只有在整个 body 都处理完之后才能计算出来。Trailer 机制解决了这个问题——先发送 body，最后再追加头部。

## Chunked 编码的消息格式

### 无 Trailer（常见格式）

```
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
\r\n
4\r\n          ← 数据块大小（十六进制）
Wiki\r\n       ← 数据块内容 + CRLF
5\r\n
pedia\r\n
0\r\n          ← 终止块（大小为 0，表示 body 结束）
\r\n           ← 空行，消息结束
```

### 有 Trailer（含尾部头部）

```
HTTP/1.1 200 OK\r\n
Transfer-Encoding: chunked\r\n
Trailer: X-Digest\r\n          ← 声明哪些字段会出现在 trailer 中
\r\n
4\r\n
Wiki\r\n
5\r\n
pedia\r\n
0\r\n          ← 终止块
X-Digest: sha256=abc123\r\n    ← trailer 头部
\r\n           ← 空行，trailer 段结束，消息结束
```

关键区别：`0\r\n` 之后不是直接 `\r\n`（空行），而是先出现 trailer 头部行，最后再以 `\r\n`（空行）结束。

## Trailer 的适用场景

1. **内容校验** — 发送方在完整 body 传输完后才能算出 hash，通过 trailer 传递校验值：
   ```
   Trailer: Content-MD5
   0\r\n
   Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n
   \r\n
   ```

2. **流式处理的元数据** — 大文件分块传输完成后，追加最终状态信息（如处理结果、耗时）

3. **分块上传的最终确认** — 服务端逐块接收数据后，在 trailer 中返回上传结果

## RFC 7230 规则

根据 RFC 7230 Section 4.1.2：

1. **`Trailer` 头部**：发送方应在初始头部中用 `Trailer` 字段声明哪些字段会出现在 trailer 段，让接收方提前知道需要缓存哪些 trailer 字段

2. **禁止出现在 Trailer 中的字段**：以下头部不允许出现在 trailer 段（因为它们会影响消息的分帧或路由）：
   - `Transfer-Encoding` — 影响消息分帧
   - `Content-Length` — 影响消息长度判定
   - `Host` — 影响请求路由
   - `Connection`、`Keep-Alive` — hop-by-hop 头部
   - `Proxy-Authenticate`、`Proxy-Authorization` — 代理认证
   - `TE`、`Trailer`、`Upgrade` — 其他 hop-by-hop 头部

3. **Trailer 是可选的**：接收方必须能处理有 trailer 和无 trailer 两种情况。没有 `Trailer` 头部声明不代表 trailer 段一定为空。

## 在 OpenScanProxy 中的处理

OpenScanProxy 作为代理，对 trailer 的核心职责是**正确转发**：

### 解析层

`decode_chunked_body()` 识别 `0\r\n` 后的 trailer 头部，逐行解析 `name: value` 格式，存储到 `HttpRequest.trailers` 或 `HttpResponse.trailers` 中。无 trailer 时该字段为空。

### 流式读取层

三处流式消息边界检测（`handle_client`、`ssl_read_http_message`、`handle_http_forward`）使用 `find_chunked_message_end()` 替代原来对 `"\r\n0\r\n\r\n"` 的固定匹配：

- 搜索 `"\r\n0\r\n"` 定位终止块
- 从终止块后搜索 `"\r\n\r\n"` 匹配 trailer 段结束
- 无 trailer 时退化为原来的 `"\r\n0\r\n\r\n"` 行为

### 序列化层

`encode_chunked_body()` 在终止块 `0\r\n` 后写入 trailer 头部（跳过 RFC 禁止字段），以空行 `\r\n` 结束。`serialize_request()` 和 `serialize_response()` 自动包含 trailers。

### MITM HTTPS 路径

原始字节直接转发（包含 trailer），同时解析用于扫描。解析失败不再导致整个消息被拒绝。

## 格式错误处理

| 错误类型 | 处理方式 |
|---|---|
| trailer 行无冒号（如 `invalidline`） | `decode_chunked_body()` 返回 `false`，整个消息解析失败 |
| 禁止字段出现在 trailer | 序列化时自动跳过，不影响解析 |
| trailer 段缺少终止空行 | 流式读取继续等待数据，直到连接关闭 |
| 无 trailer（`0\r\n\r\n`） | 正常处理，trailers 字段为空 |

## 与其他 HTTP 机制的关系

| 机制 | 区别 |
|---|---|
| 普通头部（headers） | 在 body 之前发送，影响消息分帧和路由 |
| Trailer | 在 body 之后发送，仅作为补充元数据 |
| Chunk extensions | 在块大小行中（如 `5;ext=val\r\n`），是块级别的元数据 |
| 尾部 CRLF | 每个 chunk 数据后的 `\r\n`，是 chunked 编码的分隔符，不是 trailer |

## 参考文档

- RFC 7230 Section 4.1: Chunked Transfer Encoding
- RFC 7230 Section 4.1.2: Chunked Trailer Part
- RFC 7230 Section 4.4: Incomplete Payloads and Trailer Fields