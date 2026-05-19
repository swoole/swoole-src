# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

### Traditional PHP Extension Build (for production use)
```bash
phpize && ./configure [flags] && make -j$(nproc) && make install
```
Common configure flags: `--enable-sockets`, `--enable-mysqlnd`, `--enable-swoole-curl`, `--enable-cares`, `--enable-swoole-pgsql`, `--with-openssl-dir=DIR`, `--enable-swoole-thread`, `--enable-iouring`, `--enable-uring-socket`

### Developer Build (with ASAN + warnings)
```bash
phpize && ./configure --enable-swoole-dev --enable-debug-log --enable-sockets --enable-mysqlnd --enable-swoole-curl
```

### CMake Build (for core lib development without full PHP build)
```bash
mkdir -p build && cd build && cmake .. && make -j$(nproc)
```
This produces `lib/libswoole.so` (core library) and `core-tests` (Google Test binary for C++ tests).

Optional CMake flags: `-DCODE_COVERAGE=ON`, `-Denable_asan=ON`, `-Denable_thread=ON`, `-Dphp_dir=PATH`, `-Dopenssl_dir=PATH`

### Running Tests

**PHP tests** (phpt format, run from repo root):
```bash
# Run all tests
php run-tests.php tests/

# Run a single test
php run-tests.php tests/swoole_coroutine/array.phpt

# Run a specific test directory
php run-tests.php tests/swoole_http_server/
```
Requires Swoole extension installed. Tests use phpt format (PHP's standard test format with `--FILE--` / `--EXPECT--` sections). Environment variables: `SWOOLE_DEBUG`, `SWOOLE_TRACE_FLAGS`.

**Core C++ tests** (Google Test, requires CMake build):
```bash
mkdir -p build && cd build && cmake .. && make -j$(nproc)
./core-tests                           # run all
./core-tests --gtest_filter="Server.*" # run subset
```

### Code Style (PHP)
```bash
composer install -d tests/include/lib  # install php-cs-fixer
./php-cs-fix                           # fix code style
```

## Architecture

### Two-Layer Structure

Swoole is a PHP extension with a C++ core library underneath:

- **`src/`** — Core C++ library (`libswoole`). Platform-agnostic event loop, coroutine engine, networking, and protocols. Does NOT depend on PHP.
- **`ext-src/`** — PHP extension layer (`ext-swoole`). Bridges the core library to PHP via Zend Engine APIs (classes, functions, resource types). Every file here corresponds to a PHP-facing class or feature.
- **`thirdparty/`** — Bundled third-party code (hiredis, llhttp, nghttp2, boost context ASM, multipart parser, PHP internal shims).

### Key Source Subsystems (`src/`)

| Directory | Purpose |
|-----------|---------|
| `core/` | Base utilities: logging, timers, string handling, error codes, channel, buffer |
| `reactor/` | Event loop implementations: **epoll** (Linux), **kqueue** (macOS/BSD), **poll** (fallback), **iocp** (Windows) |
| `coroutine/` | Coroutine scheduler, context switching (boost asm/ucontext/thread), socket/file hooks, io_uring integration |
| `server/` | Server modes: multi-process (`master.cc`/`manager.cc`/`worker.cc`), multi-thread, task workers, static file handler |
| `network/` | Low-level networking: TCP/UDP client/server sockets, DNS resolution |
| `protocol/` | Wire protocols: HTTP/1.1, HTTP/2, WebSocket, MQTT, Redis protocol, SOCKS5 proxy, SSL/TLS/DTLS |
| `lock/` | Synchronization primitives: mutex, rwlock, spinlock, barrier, coroutine-aware lock |
| `memory/` | Shared memory data structures: Table, LRU cache, ring buffer |
| `os/` | OS abstractions: signals, pipes, process pool, message queue |
| `wrapper/` | C++ header-only wrappers for coroutine-aware PHP stream functions |

### Coroutine Engine

Coroutines are cooperatively-scheduled user-space threads. Key concepts:
- Context switching uses **boost.context ASM** (per CPU arch) or POSIX `ucontext` or `SW_USE_THREAD_CONTEXT`.
- The **hook** mechanism (`src/coroutine/hook.cc`) intercepts blocking PHP stream/network calls and converts them to coroutine-yielding async operations.
- Runtime hooks (`SWOOLE_HOOK_ALL`) transparently make `curl`, `mysqli`, `pdo`, `redis`, `stream_socket_*`, `sleep`, `file_get_contents` coroutine-aware.

### Server Models

- **SWOOLE_PROCESS** (default): One Manager process forks N Worker processes. Workers handle connections via event loop. Task workers for async task dispatch.
- **SWOOLE_BASE**: Single-process, all workers share the event loop (no IPC overhead).
- **Thread mode** (`--enable-swoole-thread`): Uses pthreads instead of processes. Requires PHP ZTS.

### PHP Extension Layer (`ext-src/`)

Entry point: `ext-src/php_swoole.cc`. Each file maps to Swoole PHP classes:
- `swoole_server.cc` → `Swoole\Server`
- `swoole_http_server.cc` → `Swoole\Http\Server`
- `swoole_coroutine.cc` → `Swoole\Coroutine` / `Co`
- `swoole_runtime.cc` → `Swoole\Runtime`
- `swoole_curl.cc` → `Swoole\Coroutine\Curl`
- etc.

Internal header `ext-src/php_swoole_private.h` is the central include for the PHP layer.

## CI Filter Tags

Commit messages can contain filter tags to restrict which CI jobs run. Only CI jobs matching the tag execute; non-matching jobs are skipped. Behavior differs between Compile/Core tests (skip by default when filter present) and Unit tests (run by default when filter present):

| Tag | Jobs Enabled |
|-----|-------------|
| `[ubuntu]` | Ubuntu compile tests |
| `[alpine]` | Alpine compile tests |
| `[macos]` | macOS compile tests |
| `[windows]` | Windows tests |
| `[core]` | Core (C++) tests |
| `[swoole_*]` | Specific unit test directories (e.g., `[swoole_coroutine]`, `[swoole_server]`), plus framework tests |
| no filter | All jobs run |

Examples:
- `test --filter=[swoole_coroutine]` — only `swoole_coroutine/` unit tests
- `test --filter=[windows]` — only Windows unit tests

## Platform Support

- **Linux** (primary): epoll, io_uring, signalfd, eventfd, sendfile. Full feature set.
- **macOS**: kqueue. Some features unavailable (io_uring, signalfd, eventfd).
- **Windows/Cygwin** (experimental): IOCP reactor. See `config.w32`, `ext-src/swoole_event.cc`.
- **Architectures**: x86_64, ARM64, ARM32, MIPS32/64, RISC-V 64, LoongArch 64 (each needs matching ASM context in `thirdparty/boost/asm/`).

## include/ Structure

Headers in `include/` are the public API of `libswoole`. Key headers:
- `swoole.h` — master include, pulls in everything
- `swoole_config.h` — compile-time feature flags
- `swoole_version.h` — version macros
- `swoole_server.h` — server structs and API
- `swoole_coroutine.h` — coroutine scheduler types
- `swoole_reactor.h` — event loop interface
- `swoole_http.h`, `swoole_http2.h`, `swoole_websocket.h` — protocol types
- `swoole_socket.h`, `swoole_socket_hook.h` — socket and hook interfaces
- `swoole_thread.h` — threading API
- `swoole_iouring.h` — io_uring integration
- `swoole_win32.h`, `swoole_iocp.h`, `swoole_iocp_socket.h` — Windows support
