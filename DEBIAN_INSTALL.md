# Debian 系统 HTTP/3 安装指南

## 重要说明

Debian APT 仓库中的 `libngtcp2-dev` **只支持 GnuTLS**，但 Swoole HTTP/3 需要 **OpenSSL 版本**的 ngtcp2。

因此，在 Debian 上必须**从源码编译**安装依赖库。

## 快速安装（推荐）

使用自动构建脚本：

```bash
cd /home/user/swoole-src
./build_http3.sh
```

这个脚本会自动完成所有步骤。

## 手动安装步骤

### 1. 安装系统依赖

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    libssl-dev \
    php-dev \
    php-cli \
    git \
    wget
```

**注意**：不要安装 `libngtcp2-dev`，因为它是 GnuTLS 版本！

### 2. 编译安装 ngtcp2（OpenSSL 版本）

```bash
# 下载源码
cd /tmp
git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2

# 配置（重点：使用 --with-openssl）
autoreconf -i

# 使用 CFLAGS 避免汇编器问题（直接在 configure 中指定）
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local \
    --with-openssl \
    --enable-lib-only

# 编译安装
make -j$(nproc)
sudo make install
```

**重要参数说明**：
- `--with-openssl` - 使用 OpenSSL 加密（必需）
- `--enable-lib-only` - 只编译库，不编译客户端/服务器工具
- `CFLAGS="-O2 -g0"` - 禁用调试信息，避免汇编器 `.base64` 伪操作错误

### 3. 编译安装 nghttp3

```bash
# 下载源码
cd /tmp
git clone --depth 1 --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
cd nghttp3

# 配置
autoreconf -i

# 使用 CFLAGS 避免汇编器问题（直接在 configure 中指定）
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local \
    --enable-lib-only

# 编译安装
make -j$(nproc)
sudo make install
```

### 4. 更新库缓存

```bash
sudo ldconfig
```

### 5. 验证安装

```bash
# 检查 ngtcp2
pkg-config --modversion ngtcp2
# 应该输出: 1.16.0

pkg-config --libs ngtcp2
# 应该包含: -lngtcp2

# 检查 ngtcp2_crypto_quictls（OpenSSL版本）
ls -la /usr/local/lib/libngtcp2_crypto_quictls*
# 应该看到: libngtcp2_crypto_quictls.so*

# 检查 nghttp3
pkg-config --modversion libnghttp3
# 应该输出: 1.12.0
```

### 6. 编译 Swoole

```bash
cd /home/user/swoole-src

# 清理之前的构建
make clean 2>/dev/null || true
phpize --clean 2>/dev/null || true

# 初始化
phpize

# 配置（指定库路径）
./configure \
    --enable-swoole \
    --enable-openssl \
    --enable-http2 \
    --with-ngtcp2-dir=/usr/local \
    --with-nghttp3-dir=/usr/local

# 编译
make -j$(nproc)

# 安装
sudo make install
```

### 7. 启用 Swoole 扩展

```bash
# 获取 PHP 版本
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')

# 创建配置文件
echo "extension=swoole.so" | sudo tee /etc/php/${PHP_VERSION}/cli/conf.d/20-swoole.ini

# 如果有 FPM
echo "extension=swoole.so" | sudo tee /etc/php/${PHP_VERSION}/fpm/conf.d/20-swoole.ini
```

### 8. 验证 HTTP/3 支持

```bash
# 检查 Swoole 已加载
php -m | grep swoole

# 检查 HTTP/3 支持
php -r 'var_dump(SWOOLE_USE_HTTP3);'
# 应该输出: bool(true)

# 查看 Swoole 版本
php --ri swoole | grep -i version
```

## 常见问题

### Q1: 编译时出现 `.base64` 汇编器错误

**错误信息**：
```
/tmp/ccXXXXXX.s: Assembler messages:
/tmp/ccXXXXXX.s:XXXX: Error: unknown pseudo-op: `.base64'
```

**原因**：某些编译器版本生成的调试信息格式与汇编器不兼容。

**解决方法**：
```bash
# 在 configure 命令中直接指定 CFLAGS 禁用调试信息
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local --with-openssl --enable-lib-only
make -j$(nproc)
```

**注意**：必须在 configure 命令前直接指定 CFLAGS，使用 export 在 sudo 环境下可能无效。

我们的构建脚本已经包含了这个修复。

### Q2: configure 找不到 ngtcp2

**错误信息**：
```
checking for ngtcp2... no
configure: error: ngtcp2 not found
```

**解决方法**：
```bash
# 确认库已安装
ls -la /usr/local/lib/libngtcp2*
ls -la /usr/local/lib/pkgconfig/ngtcp2.pc

# 更新 pkg-config 路径
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# 重新运行 configure
./configure --with-ngtcp2-dir=/usr/local ...
```

### Q2: 运行时找不到共享库

**错误信息**：
```
error while loading shared libraries: libngtcp2.so.9: cannot open shared object file
```

**解决方法**：
```bash
# 更新库缓存
sudo ldconfig

# 或者设置环境变量
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### Q3: 编译时链接错误

**错误信息**：
```
undefined reference to `ngtcp2_crypto_quictls_*'
```

**原因**：使用了 GnuTLS 版本的 ngtcp2

**解决方法**：
```bash
# 卸载 APT 安装的包
sudo apt-get remove libngtcp2-dev libngtcp2-crypto-gnutls-dev

# 从源码重新编译安装 OpenSSL 版本
# 参考上面的步骤 2
```

### Q4: 如何检查使用的是哪个版本？

```bash
# 检查链接的库
ldd /usr/lib/php/$(php -r 'echo PHP_MAJOR_VERSION;')*/swoole.so | grep ngtcp2

# 应该看到：
# libngtcp2_crypto_quictls.so.2 => /usr/local/lib/libngtcp2_crypto_quictls.so.2
# libngtcp2.so.9 => /usr/local/lib/libngtcp2.so.9

# 不应该看到 gnutls！
```

## 为什么不能用 APT 包？

Debian APT 仓库中的 ngtcp2 包结构：

```
❌ 不可用的包：
libngtcp2-dev              → 基础库（只有核心功能）
libngtcp2-crypto-gnutls-dev → GnuTLS 加密（不兼容）
libngtcp2-crypto-gnutls2   → GnuTLS 运行时库

✅ 我们需要（需从源码编译）：
libngtcp2                  → 基础库
libngtcp2_crypto_quictls   → OpenSSL 加密（Swoole 使用）
```

Swoole 的实现基于 OpenSSL 3.0+，使用了 `ngtcp2_crypto_quictls` API，这与 GnuTLS 版本不兼容。

## 版本要求

| 组件 | 最低版本 | 推荐版本 |
|------|---------|---------|
| ngtcp2 | 1.16.0 | 1.16.0+ |
| nghttp3 | 1.12.0 | 1.12.0+ |
| OpenSSL | 3.0.0 | 3.0.13+ |
| PHP | 8.0 | 8.1+ |

## 完整的安装脚本

保存为 `install_debian.sh`：

```bash
#!/bin/bash
set -e

echo "正在安装 Swoole HTTP/3 支持（Debian 专用）..."

# 1. 安装系统依赖
sudo apt-get update
sudo apt-get install -y build-essential autoconf libtool pkg-config \
    libssl-dev php-dev php-cli git wget

# 2. 编译 ngtcp2（OpenSSL 版本）
cd /tmp
rm -rf ngtcp2
git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -i
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local --with-openssl --enable-lib-only
make -j$(nproc)
sudo make install

# 3. 编译 nghttp3
cd /tmp
rm -rf nghttp3
git clone --depth 1 --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
cd nghttp3
autoreconf -i
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local --enable-lib-only
make -j$(nproc)
sudo make install

# 4. 更新库缓存
sudo ldconfig

# 5. 验证
pkg-config --modversion ngtcp2
pkg-config --modversion libnghttp3
ls -la /usr/local/lib/libngtcp2_crypto_quictls.so*

# 6. 编译 Swoole
cd /home/user/swoole-src
make clean 2>/dev/null || true
phpize --clean 2>/dev/null || true
phpize
./configure --enable-swoole --enable-openssl --enable-http2 \
    --with-ngtcp2-dir=/usr/local --with-nghttp3-dir=/usr/local
make -j$(nproc)
sudo make install

# 7. 启用扩展
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "extension=swoole.so" | sudo tee /etc/php/${PHP_VERSION}/cli/conf.d/20-swoole.ini

# 8. 验证
php -r 'var_dump(SWOOLE_USE_HTTP3);'

echo "安装完成！"
```

## 运行示例

```bash
# 生成 SSL 证书
cd examples
./generate_ssl_cert.sh

# 运行服务器（使用高端口避免权限问题）
php http3_advanced_server.php
```

## 相关链接

- [Debian ngtcp2 包信息](https://packages.debian.org/search?keywords=ngtcp2)
- [ngtcp2 官方文档](https://nghttp2.org/ngtcp2/)
- [完整构建指南](HTTP3_BUILD_GUIDE.md)
- [快速入门](HTTP3_QUICKSTART.md)
