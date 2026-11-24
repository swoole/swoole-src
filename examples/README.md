# Swoole examples

Runnable samples for Swoole 6.x. Most files are small, self-contained PHP
scripts: each one demonstrates a single idea. Start with **Getting started**
below, then follow the table for the area you are interested in.

`Level` tells you how much background a sample assumes. `Run mode` says how to
run it:

| Run mode | Meaning |
| --- | --- |
| `CLI` | Run `php file.php`; it finishes by itself. |
| `Server` | A long-running server; press `Ctrl+C` to stop. |
| `C/S pair` | Start the server named in `Requires` in another terminal first. |
| `Smoke` | Only checked for syntax / startup, needs external services. |

`Requires` lists extra prerequisites: a free local port, a server from another
file, the shared TLS certificates, a ZTS build, or an external service.

## Getting started

Read these in order. Each is under 40 lines and needs no external service.

| # | Example | What you learn |
| --- | --- | --- |
| 1 | [coroutine/hello.php](coroutine/hello.php) | `Swoole\Coroutine\run()` and `Coroutine::create()` |
| 2 | [coroutine/channel_basic.php](coroutine/channel_basic.php) | Passing data between coroutines with `Channel` |
| 3 | [coroutine/waitgroup.php](coroutine/waitgroup.php) | Waiting for several tasks with `WaitGroup` |
| 4 | [http/hello.php](http/hello.php) | A minimal HTTP server |
| 5 | [http/client_get.php](http/client_get.php) | Calling that server with a coroutine HTTP client |
| 6 | [timer/tick_basic.php](timer/tick_basic.php) | Repeating work with `Swoole\Timer::tick()` |
| 7 | [table/usage.php](table/usage.php) | Shared memory with `Swoole\Table` |
| 8 | [client/simple.php](client/simple.php) | A synchronous TCP client |

## How to run

```shell
php examples/coroutine/hello.php        # a CLI sample
php examples/http/hello.php             # a server; curl 127.0.0.1:9501/ elsewhere
```

- The `swoole` extension must be loaded. The historical samples use short
  names (`go()`, `Co\`), so `swoole.use_shortname=On` is needed for those; all
  newly added samples use full `Swoole\...` names and do not need it.
- Server samples bind fixed local ports (mostly 9501–9510). Stop one before
  starting another sample on the same port.
- Samples that need a partner print a short hint instead of crashing when the
  server is not running.

## Building the C++ examples (libswoole)

`cpp/` contains C++ programs that link against **libswoole** (the C++ library),
not against `ext-swoole` (the PHP extension `modules/swoole.so`). They are built
with CMake, which knows the versioned library name; a bare `-lswoole` cannot
find `lib/libswoole.so.<version>`.

```shell
cmake .
cmake --build . --target lib-swoole --parallel 1
cmake --build . --target test_server --parallel 1
./bin/test_server
```

`make -C examples/cpp all` is a thin wrapper around the same commands for the
`co`, `repeat` and `test_server` targets. See [cpp/Makefile](cpp/Makefile) and
[docs/TESTS.md](../docs/TESTS.md).

## Certificates

The TLS samples do not ship certificates. They reuse the test suite's files in
`tests/include/ssl_certs/` through [ssl/certs.php](ssl/certs.php):

```php
require __DIR__ . '/certs.php';
$server->set([
    'ssl_cert_file' => SSL_CERT_DIR . 'server.crt',
    'ssl_key_file'  => SSL_CERT_DIR . 'server.key',
]);
```

See [ssl/gen_cert.md](ssl/gen_cert.md) if you want to generate a throwaway
self-signed certificate for local experiments. Never commit certificate files.

## Temporary files & cleanup

Some samples write a file (downloads, hook demos, debug logs). Every such sample
registers a shutdown cleanup so the working tree stays clean, and `.gitignore`
covers the generated names (`*.log`, `data.txt`, `recv_file_*.jpg`, `*.xyz`,
`test_link.jpg`, ...). Fixtures used by the test suite — `test.jpg`, `www/`,
`http/moc.moc` — are intentional and must stay where they are.

## Server and task workers

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [single.php](server/single.php) | The smallest TCP server | Beginner | Server | free port |
| [tcp_server.php](server/tcp_server.php) | Classic TCP echo server | Intermediate | Server | free port |
| [stats.php](server/stats.php) | `Server::stats()` | Beginner | Server | free port |
| [port.php](server/port.php) | TCP + UDP listeners on one server | Intermediate | Server | free ports |
| [task/basic.php](task/basic.php) | `task()` / `finish()` offload | Beginner | Server | free port |
| [redis_server.php](server/redis_server.php) | A tiny Redis-protocol server | Intermediate | Server | free port |
| [server/mixed.php](server/mixed.php) | 460-line "everything" demo | Advanced | Server | many features |

`server/` (35 files) and `task/` (10 files) also contain dispatch, reload,
proxy, pool and hot-update samples; most are Advanced legacy demos.

## HTTP, WebSocket and HTTP/2

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [hello.php](http/hello.php) | Minimal HTTP server | Beginner | Server | free port |
| [client_get.php](http/client_get.php) | Coroutine HTTP GET | Beginner | C/S pair | http/hello.php |
| [client_post.php](http/client_post.php) | Coroutine HTTP POST | Beginner | C/S pair | http/hello.php |
| [cookie.php](http/cookie.php) | Building a `Set-Cookie` header | Beginner | CLI | — |
| [static_handler.php](http/static_handler.php) | Serving static files | Beginner | Server | — |
| [http_server_hello.php](coroutine/http_server_hello.php) | Coroutine HTTP server | Beginner | Server | free port |
| [broadcast.php](websocket/broadcast.php) | Broadcast to all WebSocket clients | Beginner | Server | free port |
| [client_basic.php](websocket/client_basic.php) | Connect, push, receive | Beginner | C/S pair | broadcast.php |
| [server_basic.php](http2/server_basic.php) | Minimal HTTPS + HTTP/2 server | Intermediate | Server | ssl certs |
| [client_get.php](http2/client_get.php) | Coroutine HTTP/2 GET | Intermediate | C/S pair | server_basic.php |
| [http/server.php](http/server.php), [coroutine/httpmulti.php](coroutine/httpmulti.php) | Comprehensive HTTP demos | Advanced | Server | — |

## Coroutines and channels

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [hello.php](coroutine/hello.php) | First coroutine program | Beginner | CLI | — |
| [channel_basic.php](coroutine/channel_basic.php) | Producer / consumer | Beginner | CLI | — |
| [channel_timeout.php](coroutine/channel_timeout.php) | `pop()` with a timeout | Beginner | CLI | — |
| [waitgroup.php](coroutine/waitgroup.php) | Built-in `WaitGroup` | Beginner | CLI | — |
| [barrier.php](coroutine/barrier.php) | Built-in `Barrier` | Beginner | CLI | — |
| [system_dns_lookup.php](coroutine/system_dns_lookup.php) | `System::dnsLookup()` | Beginner | CLI | — |
| [system_exec.php](coroutine/system_exec.php) | `System::exec()` | Beginner | CLI | — |
| [system_file_io.php](coroutine/system_file_io.php) | `System::readFile()` / `writeFile()` | Beginner | CLI | — |
| [iouring.php](coroutine/iouring.php) | io_uring-aware `sleep()` | Beginner | CLI | — |
| [socket/tcp_echo.php](coroutine/socket/tcp_echo.php) | `Coroutine\Socket` server + client | Intermediate | CLI | — |
| [coroutine/select/](coroutine/select/), [coroutine/behavior/](coroutine/behavior/), [coroutine/stack/](coroutine/stack/) | Select, scheduler and C-stack experiments | Advanced | CLI | — |

## Timers and events

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [tick_basic.php](timer/tick_basic.php) | Repeating `Timer::tick()` | Beginner | CLI | — |
| [after_basic.php](timer/after_basic.php) | One-shot `Timer::after()` | Beginner | CLI | — |
| [clear_basic.php](timer/clear_basic.php) | `Timer::clear()` / `exists()` | Beginner | CLI | — |
| [event/stdin.php](event/stdin.php) | `Swoole\Event` on stdin | Intermediate | CLI | — |
| [timer/tick.php](timer/tick.php), [timer/after.php](timer/after.php) | Multi-timer string-callback demos | Advanced | CLI | — |

## Clients

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [simple.php](client/simple.php) | Synchronous TCP client | Beginner | C/S pair | a TCP server |
| [coro_echo.php](client/coro_echo.php) | `Coroutine\Client` | Beginner | C/S pair | server/port.php |
| [curl/single_request.php](curl/single_request.php) | One hooked curl request | Beginner | C/S pair | http/hello.php |
| [client/c10k.php](client/c10k.php) | Many concurrent connections | Advanced | C/S pair | — |

## Processes and threads

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [basic.php](process/basic.php) | Fork + `Process::wait()` | Beginner | CLI | — |
| [basic.php](process_pool/basic.php) | `Process\Pool` with 2 workers | Beginner | Server | — |
| [hello.php](thread/hello.php) | One native thread | Beginner | CLI | ZTS build |
| [barrier.php](thread/barrier.php) | `Thread\Barrier` | Intermediate | CLI | ZTS build |
| [queue.php](thread/queue.php) | `Thread\Queue` between threads | Intermediate | CLI | ZTS build |
| [thread/thread_server.php](thread/thread_server.php) | Thread-based HTTP server | Advanced | Server | ZTS build |

## Shared memory and synchronization

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [usage.php](table/usage.php) | `Swoole\Table` columns and rows | Beginner | CLI | — |
| [incr_decr.php](table/incr_decr.php) | Atomic counters in a table | Beginner | CLI | — |
| [test.php](atomic/test.php) | `Swoole\Atomic` | Beginner | CLI | — |
| [basic.php](lock/basic.php) | `Swoole\Lock` | Beginner | CLI | — |

## SSL, DTLS and runtime hooks

| Example | Shows | Level | Run mode | Requires |
| --- | --- | --- | --- | --- |
| [client_basic.php](ssl/client_basic.php) | Coroutine HTTPS client | Beginner | C/S pair | ssl/webserver.php |
| [webserver.php](ssl/webserver.php) | HTTPS + HTTP/2 server | Intermediate | Server | ssl certs |
| [dtls/server.php](dtls/server.php) | DTLS server | Intermediate | Server | ssl certs |
| [hook_flags.php](runtime/hook_flags.php) | `Runtime::setHookFlags()` | Beginner | CLI | — |
| [pdo_hook.php](runtime/pdo_hook.php) | Hooked PDO (SQLite) | Beginner | CLI | pdo_sqlite |
| [unlink.php](runtime/unlink.php) | Hooked `unlink()` | Beginner | CLI | — |
| [runtime/](runtime/) 17 more | sleep, file, stream, curl, ODBC, ... hooks | Intermediate | mixed | varies |

## C++ and other modules

| Directory | Shows | Level | Requires |
| --- | --- | --- | --- |
| [cpp/](cpp/) | `libswoole` C++ programs (`co.cc`, `repeat.cc`, `test_server.cc`) | Intermediate | libswoole |
| [misc/](misc/) | `swoole_version()`, local IP / MAC helpers | Beginner | — |
| [tracer/](tracer/) | Tracing and blocking detection | Advanced | — |
| [php/](php/) | Small PHP-level / debugging snippets | Advanced | — |
| [ssl/client.c](ssl/client.c) | A plain OpenSSL client (no Swoole) | Advanced | OpenSSL |

`php/error.php` is an intentionally invalid syntax sample used as a negative
example; it is the only file excluded from `php -l` checks.

## Fixtures

`test.jpg`, `www/`, `http/moc.moc`, `http/*.txt` and `client/test.txt` are data
files used by the PHPT test suite as document roots and upload payloads. They
are not standalone samples — do not move or delete them.

## Migration notes

All samples here use the current Swoole 6.x API. Legacy examples that depended
on removed classes or server callbacks have been deleted or rewritten; a few
long, comprehensive samples remain and are marked **Advanced**. New samples use
full `Swoole\...` names and `use function Swoole\Coroutine\run;` rather than
short names, so they work regardless of `swoole.use_shortname`.
