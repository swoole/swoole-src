# 手动编译测试（解决 .base64 汇编器错误）

## 问题已修复

已在以下文件中添加 `CFLAGS="-O2 -g0"` 修复：
- ✅ build_http3.sh
- ✅ DEBIAN_INSTALL.md
- ✅ HTTP3_BUILD_GUIDE.md

## 手动测试步骤

### 1. 编译 ngtcp2

```bash
cd /tmp
rm -rf ngtcp2
git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -i

# 关键：设置 CFLAGS 避免 .base64 错误
export CFLAGS="-O2 -g0"

./configure --prefix=/usr/local --with-openssl --enable-lib-only
make -j$(nproc)
sudo make install

unset CFLAGS
```

### 2. 编译 nghttp3

```bash
cd /tmp
rm -rf nghttp3
git clone --depth 1 --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
cd nghttp3
autoreconf -i

# 关键：设置 CFLAGS 避免 .base64 错误
export CFLAGS="-O2 -g0"

./configure --prefix=/usr/local --enable-lib-only
make -j$(nproc)
sudo make install

unset CFLAGS
```

### 3. 更新库缓存

```bash
sudo ldconfig
```

### 4. 验证安装

```bash
pkg-config --modversion ngtcp2
pkg-config --modversion libnghttp3
ls -la /usr/local/lib/libngtcp2_crypto_quictls.so*
```

### 5. 编译 Swoole

```bash
cd /home/user/swoole-src
phpize
./configure --enable-swoole --enable-openssl --enable-http2 \
    --with-ngtcp2-dir=/usr/local --with-nghttp3-dir=/usr/local
make -j$(nproc)
sudo make install
```

### 6. 启用扩展

```bash
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "extension=swoole.so" | sudo tee /etc/php/${PHP_VERSION}/cli/conf.d/20-swoole.ini
```

### 7. 验证 HTTP/3

```bash
php -r 'var_dump(SWOOLE_USE_HTTP3);'
# 应该输出: bool(true)
```

## 修复说明

**问题**：
```
/tmp/ccXXXXXX.s: Assembler messages:
/tmp/ccXXXXXX.s:XXXX: Error: unknown pseudo-op: `.base64'
```

**原因**：
- GCC 生成的调试信息包含 `.base64` 汇编指令
- 某些汇编器版本不识别此指令

**解决方案**：
- `CFLAGS="-O2 -g0"` - 禁用调试信息
- `-O2` - 保持优化级别
- `-g0` - 完全禁用调试符号

## 如果仍有问题

如果编译仍然失败，可以尝试：

```bash
# 方案 2：使用 -g1（最小调试信息）
export CFLAGS="-O2 -g1"

# 方案 3：指定 DWARF 格式
export CFLAGS="-O2 -gdwarf-4"
```

## 自动化脚本

如果有 sudo 权限，直接运行：

```bash
cd /home/user/swoole-src
./build_http3.sh
```

所有修复已包含在脚本中。
