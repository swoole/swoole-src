# Swoole HTTP/3 实现计划

## 研究结论

### 当前环境
- **系统 OpenSSL 版本**: 3.0.13 (支持 TLS 1.3,但无 QUIC 服务器端支持)
- **OpenSSL QUIC 支持**:
  - OpenSSL 3.2+: QUIC 客户端支持
  - OpenSSL 3.5+: QUIC 服务器端支持
  - 注意: OpenSSL 不提供 HTTP/3 层,只提供 QUIC 传输层

### 选择的库
- **QUIC 传输层**: ngtcp2 >= 1.16.0
- **HTTP/3 应用层**: nghttp3 >= 1.12.0
- **TLS 库**: OpenSSL 3.0+ (已有)

**理由**:
1. ngtcp2/nghttp3 是成熟稳定的 QUIC/HTTP3 实现
2. curl 和 nghttpx 等主流项目都使用这个组合
3. 与 Swoole 现有的 nghttp2 架构相似,便于集成
4. 支持 OpenSSL 3.0+,兼容当前环境

## 架构设计

```
┌─────────────────────────────────────────────────────┐
│  PHP Extension Layer                                │
│  ext-src/swoole_http3_server.cc (新建)             │
│  ext-src/swoole_http3_client_coro.cc (新建)        │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  HTTP/3 Protocol Handler                            │
│  src/protocol/http3.cc (新建)                       │
│  include/swoole_http3.h (新建)                      │
│                                                      │
│  功能:                                              │
│  - HTTP/3 请求/响应处理                            │
│  - QPACK 头部压缩/解压 (通过 nghttp3)              │
│  - HTTP/3 帧处理                                    │
│  - Server Push 支持                                 │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  QUIC Connection Manager                            │
│  src/protocol/quic.cc (新建)                        │
│  include/swoole_quic.h (新建)                       │
│                                                      │
│  功能:                                              │
│  - QUIC 连接管理 (通过 ngtcp2)                     │
│  - 流管理 (stream creation/control)                │
│  - 流量控制 (flow control)                         │
│  - 连接迁移 (connection migration)                 │
│  - 拥塞控制 (congestion control)                   │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  TLS 1.3 Integration                                │
│  扩展 src/protocol/ssl.cc                           │
│  扩展 include/swoole_ssl.h                          │
│                                                      │
│  功能:                                              │
│  - QUIC TLS 握手                                    │
│  - 0-RTT 支持                                       │
│  - Session resumption                               │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  UDP Socket Layer                                   │
│  扩展 src/network/socket.cc                         │
│                                                      │
│  功能:                                              │
│  - UDP socket 支持                                  │
│  - 与 Reactor 集成                                  │
│  - UDP 数据报收发                                   │
└─────────────────────────────────────────────────────┘
```

## 实现步骤

### 阶段 1: 基础设施和依赖 (当前)
- [x] 研究 QUIC/HTTP3 库选项
- [ ] 更新 config.m4 添加 ngtcp2/nghttp3 支持
- [ ] 创建基础头文件和结构定义
- [ ] 添加编译选项 `--with-ngtcp2-dir` 和 `--with-nghttp3-dir`

### 阶段 2: QUIC 传输层
- [ ] 实现 QUIC 连接管理 (swoole_quic.h, quic.cc)
- [ ] 实现 QUIC 流管理
- [ ] 集成 TLS 1.3 握手
- [ ] 实现流量控制和拥塞控制
- [ ] 与 Swoole Reactor 集成

### 阶段 3: HTTP/3 协议层
- [ ] 实现 HTTP/3 帧处理 (swoole_http3.h, http3.cc)
- [ ] 实现 QPACK 头部压缩 (通过 nghttp3)
- [ ] 实现请求/响应处理
- [ ] 实现 Server Push 功能

### 阶段 4: PHP 扩展接口
- [ ] 创建 Swoole\Http3\Server 类
- [ ] 创建 Swoole\Http3\Request 类
- [ ] 创建 Swoole\Http3\Response 类
- [ ] 添加配置选项 (类似 HTTP/2)

### 阶段 5: 测试和文档
- [ ] 编写单元测试
- [ ] 编写集成测试
- [ ] 性能测试
- [ ] 更新文档

## 配置选项设计

### config.m4 新增选项
```m4
PHP_ARG_WITH([ngtcp2-dir],
  [dir of ngtcp2],
  [AS_HELP_STRING([[--with-ngtcp2-dir[=DIR]]],
    [Include ngtcp2 QUIC support (requires ngtcp2 >= 1.16.0)])], [no], [no])

PHP_ARG_WITH([nghttp3-dir],
  [dir of nghttp3],
  [AS_HELP_STRING([[--with-nghttp3-dir[=DIR]]],
    [Include nghttp3 HTTP/3 support (requires nghttp3 >= 1.12.0)])], [no], [no])
```

### PHP 使用示例
```php
$server = new Swoole\Http3\Server("0.0.0.0", 443);

$server->set([
    'ssl_cert_file' => 'server.crt',
    'ssl_key_file' => 'server.key',
    'open_http3_protocol' => true,
    'enable_quic_0rtt' => true,
]);

$server->on('request', function ($request, $response) {
    $response->end("Hello HTTP/3!");
});

$server->start();
```

## 文件清单

### 新建文件
- `include/swoole_quic.h` - QUIC 连接和流管理头文件
- `include/swoole_http3.h` - HTTP/3 协议头文件
- `src/protocol/quic.cc` - QUIC 实现
- `src/protocol/http3.cc` - HTTP/3 实现
- `ext-src/swoole_http3_server.cc` - PHP HTTP/3 服务器扩展
- `ext-src/swoole_http3_request.cc` - HTTP/3 请求对象
- `ext-src/swoole_http3_response.cc` - HTTP/3 响应对象
- `ext-src/swoole_http3_client_coro.cc` - HTTP/3 协程客户端

### 修改文件
- `config.m4` - 添加 ngtcp2/nghttp3 编译选项
- `include/swoole_ssl.h` - 添加 QUIC TLS 支持
- `src/protocol/ssl.cc` - 扩展 TLS 1.3 for QUIC
- `src/network/socket.cc` - 添加 UDP/QUIC socket 支持

## 兼容性

### 最低版本要求
- OpenSSL >= 3.0.0
- ngtcp2 >= 1.16.0
- nghttp3 >= 1.12.0
- PHP >= 8.0

### 向后兼容
- HTTP/1.1 和 HTTP/2 保持完全兼容
- 通过 ALPN 协商协议版本
- 优雅降级到 HTTP/2 或 HTTP/1.1

## 性能优化

### 计划优化点
1. **0-RTT 连接**: 减少握手延迟
2. **连接迁移**: 支持 IP 地址变更
3. **多路复用**: 无队头阻塞
4. **流量控制**: 自适应窗口大小
5. **内存池**: 减少内存分配开销

## 安全考虑

1. **TLS 1.3 强制**: QUIC 必须使用 TLS 1.3
2. **连接 ID 保护**: 防止连接跟踪
3. **地址验证**: 防止 DDoS 放大攻击
4. **密钥更新**: 支持定期密钥轮换

## 参考资料

- RFC 9000: QUIC Transport Protocol
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- RFC 9114: HTTP/3
- RFC 9204: QPACK: Field Compression for HTTP/3
- ngtcp2 文档: https://github.com/ngtcp2/ngtcp2
- nghttp3 文档: https://github.com/ngtcp2/nghttp3
