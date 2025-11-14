# HTTP/3 Quick Start Guide

快速开始使用Swoole HTTP/3服务器。

## 一、安装依赖并编译

### 方法1：自动安装（推荐）

```bash
# 运行自动构建脚本
./build_http3.sh
```

这个脚本会自动完成：
- 安装系统依赖
- 编译安装 ngtcp2 (QUIC库)
- 编译安装 nghttp3 (HTTP/3库)
- 编译 Swoole 并启用 HTTP/3 支持
- 验证安装

### 方法2：手动安装

详细步骤请参考：[HTTP3_BUILD_GUIDE.md](HTTP3_BUILD_GUIDE.md)

## 二、生成SSL证书

HTTP/3 要求使用 HTTPS，需要SSL证书：

```bash
cd examples
./generate_ssl_cert.sh
```

## 三、运行示例服务器

### 简单示例

```bash
# 运行简单的HTTP/3服务器
php examples/http3_server.php
```

### 高级示例（推荐）

```bash
# 运行功能完整的HTTP/3服务器
php examples/http3_advanced_server.php
```

## 四、测试服务器

### 使用 curl

```bash
# 基本测试
curl --http3 -k https://localhost:8443/

# 测试JSON端点
curl --http3 -k https://localhost:8443/json

# 查看服务器统计
curl --http3 -k https://localhost:8443/stats
```

### 使用浏览器

1. 打开 Chrome/Edge
2. 访问 `chrome://flags/#enable-quic`
3. 启用 "Experimental QUIC protocol"
4. 重启浏览器
5. 访问 `https://localhost:8443/`
6. 接受自签名证书警告
7. 您将看到: "hello from http3 server!"

## 五、示例代码

最简单的HTTP/3服务器：

```php
<?php

// 检查HTTP/3支持
if (!SWOOLE_USE_HTTP3) {
    die("HTTP/3 not supported\n");
}

// 创建HTTP/3服务器
$server = new Swoole\Http3\Server("0.0.0.0", 8443);

// 配置SSL证书
$server->set([
    'ssl_cert_file' => 'cert.pem',
    'ssl_key_file'  => 'key.pem',
]);

// 处理请求
$server->on('request', function ($request, $response) {
    $response->end("hello from http3 server!\n");
});

// 启动服务器
$server->start();
```

## 六、验证HTTP/3是否启用

```bash
# 检查Swoole是否编译了HTTP/3支持
php -r 'var_dump(SWOOLE_USE_HTTP3);'
# 输出: bool(true)

# 查看Swoole版本
php --ri swoole | grep -i http3
```

## 七、可用端点（高级示例）

运行 `http3_advanced_server.php` 后，可访问：

- `GET /` - 简单的hello消息
- `GET /json` - JSON格式响应
- `GET /headers` - 显示所有请求头
- `GET /query?key=value` - 查询参数解析
- `GET /cookie` - Cookie处理
- `GET /stats` - 服务器统计信息
- `GET /info` - 服务器详细信息
- `GET /large?size=1024` - 大文件响应测试
- `GET /stream` - 流式响应

## 八、常见问题

### Q: 端口443需要root权限？

**A:** 是的。有两个解决方案：
1. 使用 sudo 运行: `sudo php examples/http3_server.php`
2. 使用高端口(>1024): 修改代码中的端口为8443

### Q: 编译时找不到库？

**A:** 确保已安装依赖：
```bash
# 检查库是否安装
pkg-config --exists ngtcp2 && echo "ngtcp2 OK"
pkg-config --exists libnghttp3 && echo "nghttp3 OK"

# 更新库缓存
sudo ldconfig
```

### Q: curl不支持HTTP/3？

**A:** 确保curl版本 >= 7.66 并编译了HTTP/3支持：
```bash
curl --version | grep HTTP3
```

如果没有HTTP/3支持，建议使用浏览器测试。

### Q: 防火墙阻止连接？

**A:** HTTP/3使用UDP协议，确保开放UDP端口：
```bash
# UFW
sudo ufw allow 8443/udp

# iptables
sudo iptables -A INPUT -p udp --dport 8443 -j ACCEPT
```

## 九、性能优化

### 系统设置

增加UDP缓冲区大小：

```bash
# 编辑 /etc/sysctl.conf
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000

# 应用设置
sudo sysctl -p
```

### 服务器配置

```php
$server->set([
    'http3_max_field_section_size' => 65536,  // 增大头部限制
    'http3_qpack_max_table_capacity' => 8192, // 更好的压缩
    'http3_qpack_blocked_streams' => 200,     // 更多并发流
]);
```

## 十、架构说明

Swoole HTTP/3 实现采用三层架构：

```
┌─────────────────────────────────┐
│    PHP Extension Layer          │  ← Swoole\Http3\Server
│  (ext-src/swoole_http3_server)  │    Swoole\Http3\Request
└─────────────────────────────────┘    Swoole\Http3\Response
                ↓
┌─────────────────────────────────┐
│   HTTP/3 Protocol Layer         │  ← swoole::http3::Server
│   (src/protocol/http3.cc)       │    swoole::http3::Connection
└─────────────────────────────────┘    swoole::http3::Stream
                ↓
┌─────────────────────────────────┐
│   QUIC Transport Layer          │  ← swoole::quic::Server
│   (src/protocol/quic.cc)        │    swoole::quic::Connection
└─────────────────────────────────┘    swoole::quic::Stream
                ↓
┌─────────────────────────────────┐
│   External Libraries            │  ← ngtcp2 (QUIC)
│                                 │    nghttp3 (HTTP/3)
└─────────────────────────────────┘    OpenSSL (TLS 1.3)
```

## 十一、下一步

- 阅读完整文档: [README-HTTP3.md](README-HTTP3.md)
- 查看实现细节: [HTTP3_SUMMARY.md](HTTP3_SUMMARY.md)
- 学习更多示例: [examples/README.md](examples/README.md)
- 参考构建指南: [HTTP3_BUILD_GUIDE.md](HTTP3_BUILD_GUIDE.md)

## 十二、技术规范

- QUIC: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- HTTP/3: [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html)
- QPACK: [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html)

---

**祝您使用愉快！**

如有问题，请查阅完整文档或提交issue。
