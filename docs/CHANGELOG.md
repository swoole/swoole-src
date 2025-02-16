# Swoole Changelog

## 2024-12-16 v6.0.0
# ✨ New Feature:
- Added multi-threading support, require the ZTS version of PHP. Add `--enable-swoole-thread` option to the configure command to activate it.
- Added a new thread class `Swoole\Thread`. @matyhtf
- Introduced thread lock `Swoole\Thread\Lock`. @matyhtf
- Added thread atomic counter `Swoole\Thread\Atomic`, `Swoole\Thread\Atomic\Long`. @matyhtf
- Added safe concurrent containers `Swoole\Thread\Map`, `Swoole\Thread\ArrayList`, `Swoole\Thread\Queue`. @matyhtf
- The file asynchronous operation supports using `io_uring` as the underlying engine for file asynchronous operations. When liburing is installed and Swoole is compiled with the --enable-iouring option, the asynchronous operations of functions such as file_get_contents, file_put_contents, fopen, fclose, fread, fwrite, mkdir, unlink, fsync, fdatasync, rename, fstat, lstat, and filesize will be implemented by io_uring. @matyhtf @NathanFreeman
- Upgraded `Boost Context` to version 1.84. Now, Loongson CPUs can also support coroutines. @NathanFreeman
- Added `Swoole\Thread\Map::find()` method. @matyhtf
- Added `Swoole\Thread\ArrayList::find()` method. @matyhtf
- Added `Swoole\Thread\ArrayList::offsetUnset()` method. @matyhtf
- Added `Swoole\Process::getAffinity()` method. @matyhtf
- Added `Swoole\Thread::setName()` method. @matyhtf
- Added `Swoole\Thread::setAffinity()` method. @matyhtf
- Added `Swoole\Thread::getAffinity()` method. @matyhtf
- Added `Swoole\Thread::setPriority()` method. @matyhtf
- Added `Swoole\Thread::getPriority()` method. @matyhtf
- Added `Swoole\Thread::gettid()` method.
- The file asynchronous engine `iouring` supports multi-threaded polling mode `IORING_SETUP_SQPOLL`. @NathanFreeman
- Added `iouring_workers` to modify the number of `iouring` threads. @NathanFreeman
- Added `iouring_flags` to support modifying the `iouring` working mode. @NathanFreeman
- Added `Swoole\Thread\Barrier` for multi-thread synchronization barrier. @matyhtf
- Added new function and class to set cookies. @matyhtf @NathanFreeman
- Added `non-blocking, reentrant coroutine mutex lock`, which can be used between processes/threads without blocking them. @NathanFreeman
- `Swoole\Coroutine\Socket::getOption()` supports the `TCP_INFO` option. @matyhtf
- `Swoole\Client` synchronous blocking client supports `http` proxy. @matyhtf
- Added asynchronous non-blocking `TCP/UDP/Unix socket` client `Swoole\Async\Client`. @matyhtf
- Optimized the `Swoole\Redis\Server::format()` method to support zero-copy memory, support `redis` nested structure. @matyhtf
- Supports the high-performance compression tool `Zstd`. You only need to add `--enable-zstd` when compiling `Swoole`, and then `zstd` can be used to compress or decode responses between the `http` client and server. @NathanFreeman

# 🐛 Bug Fixed：
- Fixed the issue where installation via `pecl` was not possible. @remicollet
- Fixed the bug where setting `keepalive` was not possible for `Swoole\Coroutine\FastCGI\Client`. @NathanFreeman
- Fixed the issue where exceeding the `max_input_vars` would throw an error, causing the process to restart repeatedly. @NathanFreeman
- Fixed unknown issues caused by using `Swoole\Event::wait()` within a coroutine. @matyhtf
- Fixed the problem where `proc_open` does not support pty in coroutine mode. @matyhtf
- Fixed segmentation fault issues with `pdo_sqlite` on PHP 8.3. @NathanFreeman
- Fixed unnecessary warnings during the compilation of `Swoole`. @Appla @NathanFreeward
- Fixed the error thrown by zend_fetch_resource2_ex when `STDOUT/STDERR` are already closed. @Appla @matyhtf
- Fixed ineffective `set_tcp_nodelay` configuration. @matyhtf
- Fixed the occasional unreachable branch issue during file upload. @NathanFreeman
- Fixed the problem where setting `dispatch_func` would cause PHP's internals to throw errors. @NathanFreeman
- Fixed the deprecation of AC_PROG_CC_C99 in autoconf >= 2.70. @petk
- Capture exceptions when thread creation fails. @matyhtf
- Fixed the undefined problem with `_tsrm_ls_cache`. @jingjingxyk
- Fixed the fatal compile error with `GCC 14`. @remicollet
- Fixed the dynamic property issue in `Swoole\Http2\Request`. @guandeng
- Fixed the occasional resource unavailability issue in the `pgsql` coroutine client. @NathanFreeman
- Fixed the issue of 503 errors due to not resetting related parameters during process restart. @matyhtf
- Fixed the inconsistency between `$request->server['request_method']` and `$request->getMethod()` when `HTTP2` is enabled. @matyhtf
- Fixed incorrect `content-type` when uploading files. @matyhtf
- Fixed code errors in the `http2` coroutine client. @matyhtf
- Fixed the missing `worker_id` property in `Swoole\Server`. @cjavad
- Fixed errors related to `brotli` in `config.m4`. @fundawang
- Fixed the invalid `Swoole\Http\Response::create` under multi-threading. @matyhtf
- Fixed compilation errors in the `macos` environment. @matyhtf
- Fixed the issue of threads not being able to exit safely. @matyhtf
- Fixed the issue where the static variable for response time returned by `Swoole\Http\Response` in multi-threaded mode was not generated separately for each thread. @matyhtf @NathanFreeman
- Fixed `Fatal error` issue caused by `PHP-8.4`'s `timeout` feature in ZTS mode. @matyhtf
- Fixed compatibility issue with the `exit()` `hook` function for `PHP-8.4`. @remicollet
- Fixed the issue where `Swoole\Thread::getNativeId()` did not work in `cygwin`. @matyhtf
- Fixed the issue causing `SIGSEGV` in `Swoole\Coroutine::getaddrinfo()` method. @matyhtf
- Fixed the issue where the runtime TCP module did not support dynamically enabling SSL encryption. @matyhtf
- Fixed the issue where the HTTP client had an incorrect timeout after running for a long time. @matyhtf
- Fixed the problem where the mutex lock of `Swoole\Table` could not be used before the process exited. @matyhtf
- Fixed the failure of `Swoole\Server::stop()` when using named parameters. @matyhtf
- Fixed the crash caused by `Swoole\Thread\Map::toArray()` not copying the key. @matyhtf
- Fixed the issue of being unable to delete nested numeric keys in `Swoole\Thread\Map`. @matyhtf

# ⭐️ Kernel optimization：
- Removed unnecessary checks for `socket structs`. @petk
- Upgraded Swoole Library. @deminy
- Added support for status code 451 in `Swoole\Http\Response`. @abnegate
- Synchronized `file` operation code across different PHP versions. @NathanFreeman
- Synchronized `pdo` operation code across different PHP versions. @NathanFreeman
- Optimized the code for `Socket::ssl_recv()`. @matyhtf
- Improved config.m4; some configurations can now set library locations via `pkg-config`. @NathanFreeman
- Optimized the use of dynamic arrays during `request header parsing`. @NathanFreeman
- Optimized file descriptor `fd` lifecycle issues in multi-threading mode. @matyhtf
- Optimized some fundamental coroutine logic. @matyhtf
- Upgraded the Oracle database version for CI testing. @gvenzl
- Optimized the underlying logic of `sendfile`. @matyhtf
- Replaced `PHP_DEF_HAVE` with `AC_DEFINE_UNQUOTED` in `config.m4`. @petk
- Optimized the logic related to `heartbeat`, `shutdown`, and `stop` for the server in multi-threaded mode. @matyhtf
- Optimized to avoid linking `librt` when `glibc` version is greater than 2.17. @matyhtf
- Enhanced the HTTP client to accept duplicate request headers. @matyhtf
- Optimized `Swoole\Http\Response::write()`. @matyhtf
- `Swoole\Http\Response::write()` can now send HTTP/2 protocol. @matyhtf
- Compatible with `PHP 8.4`. @matyhtf @NathanFreeman
- Added the ability for asynchronous writing at the underlying socket level. @matyhtf
- Optimized `Swoole\Http\Response`. @NathanFreeman
- Improved underlying error messages. @matyhtf
- Supported sharing PHP native sockets in multi-threaded mode. @matyhtf
- Optimized static file service and fixed static file path error issues. @matyhtf
- Multi-thread mode `SWOOLE_THREAD` supports restarting worker threads. @matyhtf
- Multi-thread mode `SWOOLE_THREAD` supports starting timers in the `Manager` thread. @matyhtf
- Compatible with the `curl` extension of `PHP-8.4`. @matyhtf @NathanFreeman
- Rewrite the underlying `Swoole` code using `iouring`. @matyhtf @NathanFreeman
- Optimized timers so that synchronous processes do not depend on signals. @matyhtf
- Optimized the `Swoole\Coroutine\System::waitSignal()` method to allow listening to multiple signals simultaneously. @matyhtf

# ❌ Deprecated：
- No longer supports `PHP 8.0`.
- No longer supports `Swoole\Coroutine\MySQL` coroutine client.
- No longer supports `Swoole\Coroutine\Redis` coroutine client.
- No longer supports `Swoole\Coroutine\PostgreSQL` coroutine client.
- Removed `Swoole\Coroutine\System::fread()`, `Swoole\Coroutine\System::fwrite()`, and `Swoole\Coroutine\System::fgets()` methods.
## 2024-01-24 v5.1.2
- Added support for embed sapi @matyhtf
- Fixed compatibility with PHP 8.3 ZEND_CHECK_STACK_LIMIT @Yurunsoft
- Fixed no Content-Range response header when the range request returns all the contents of the file @Yurunsoft
- Optimized HTTP server performance @NathanFreeman
- Fixed truncated cookie @stnguyen90
- Fixed native-curl crash on PHP 8.3 @NathanFreeman
- Added CLOSE_SERVICE_RESTART, CLOSE_TRY_AGAIN_LATER, CLOSE_BAD_GATEWAY as valid close reasons for websocket @cjavad
- Fixed invalid errno after Server::Manager::wait() @JacobBrownAustin
- Fixed HTTP2 Typo @leocavalcante

## 2022-07-22 v5.0.0

### Added
* Added `max_concurrency` option for `Server`
* Added `max_retries` option for `Coroutine\Http\Client`
* Added `name_resolver` global option
* Added `upload_max_filesize` option for `Server`
* Added `Coroutine::getExecuteTime()`
* Added `SWOOLE_DISPATCH_CONCURRENT_LB` dispatch_mode for `Server`

### Changed
* Enhanced type system, added types for parameters and return values of all functions
* Optimized error handling, all constructors will throw exceptions when fail
* Adjusted the default mode of Server, the default is `SWOOLE_BASE` mode

### Removed

- Removed `PSR-0` style class names
- Removed the automatic addition of `Event::wait()` in shutdown function
- Removed `Server::tick/after/clearTimer/defer` aliases
- Removed `--enable-http`/`--enable-swoole-json`, adjusted to be enable by default

### Deprecated
- Deprecated `Coroutine\Redis` and `Coroutine\MySQL`
