<p align="center">
  <img src="docs/swoole-logo.svg" width="200" height="120" alt="Swoole logo">
</p>

<h1 align="center">Swoole</h1>

<p align="center">An event-driven networking engine and coroutine runtime for PHP</p>

<p align="center">
  <a href="https://github.com/swoole/swoole-src/actions/workflows/ext.yml"><img src="https://github.com/swoole/swoole-src/actions/workflows/ext.yml/badge.svg" alt="Extension build"></a>
  <a href="https://github.com/swoole/swoole-src/actions/workflows/core.yml"><img src="https://github.com/swoole/swoole-src/actions/workflows/core.yml/badge.svg" alt="Core tests"></a>
  <a href="https://github.com/swoole/swoole-src/actions/workflows/unit.yml"><img src="https://github.com/swoole/swoole-src/actions/workflows/unit.yml/badge.svg" alt="PHP tests"></a>
  <a href="https://github.com/swoole/swoole-src/releases"><img src="https://img.shields.io/github/v/release/swoole/swoole-src" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/swoole/swoole-src" alt="License"></a>
</p>

Swoole is a PHP extension for building persistent network services and concurrent I/O applications. Its C/C++ core provides an event loop, coroutine scheduler, servers, clients, and protocol implementations. The bundled PHP library adds connection pools, proxies, and higher-level utilities. Use Swoole for HTTP APIs, WebSocket applications, TCP/UDP gateways, and services that need to handle many connections without a separate PHP process for every request.

> **Version note:** `master` is the development branch for Swoole 6.3 and currently supports PHP 8.2–8.5. For production, choose a released version and check the [supported versions](docs/SUPPORTED.md) for its PHP compatibility and maintenance status.

## At a glance

| Capability | Main APIs | Typical use |
| --- | --- | --- |
| Event-driven servers | `Swoole\Server`, `Swoole\Event` | TCP, UDP, Unix sockets, connection events |
| Coroutines | `Swoole\Coroutine`, `Channel`, `Socket` | Concurrent I/O and task coordination |
| HTTP and WebSocket | `Swoole\Http\Server`, `Swoole\WebSocket\Server` | APIs, streaming responses, real-time messaging |
| Coroutine clients | `Swoole\Coroutine\Client`, `Swoole\Coroutine\Http\Client` | Calls to TCP and HTTP upstream services |
| Runtime hooks | `Swoole\Runtime` | Coroutine-aware behavior for supported PHP functions |
| Processes and shared data | `Swoole\Process`, `Swoole\Table`, atomics | Background work and interprocess state |
| Timers and system I/O | `Swoole\Timer`, `Swoole\Coroutine\System` | Scheduled work, file and process operations |

## How Swoole works

The Reactor watches sockets and other registered file descriptors, then dispatches events to callbacks. Servers can run multiple worker processes to use multiple CPU cores. Within a worker, coroutines let other tasks run while one task waits for supported I/O. Task workers provide a separate execution path for jobs that should not hold up request handling.

Coroutines are a concurrency tool, not automatic CPU parallelism. A CPU-intensive PHP loop still occupies its worker until it yields or finishes. Use worker or task processes, or optional thread support, when work needs parallel execution.

Swoole workers are long-lived. Global variables, static state, and open resources can survive beyond one request. Close or recycle connections, enforce timeouts, and keep per-request data out of process-wide state. Ordinary PHP variables are not shared between worker processes; use IPC, `Table`, or external storage when data must be shared.

## Functional modules

### Servers and network protocols

`Swoole\Server` handles TCP, UDP, and Unix socket services. It supports multiple listening ports, worker and task worker processes, connection management, heartbeats, and configurable packet boundaries such as length fields or EOF markers. `Swoole\Event` lets an application register its own file descriptors with the event loop, while `Swoole\Timer` schedules one-off or recurring callbacks.

Choose the server API that matches the protocol and lifecycle:

| Requirement | Starting point |
| --- | --- |
| Custom TCP/UDP protocol, multiple ports, or task workers | `Swoole\Server` |
| HTTP API with request callbacks and worker processes | `Swoole\Http\Server` |
| HTTP service controlled from a coroutine | `Swoole\Coroutine\Http\Server` |
| WebSocket handshake and bidirectional frames | `Swoole\WebSocket\Server` |

See the [TCP server](examples/server/tcp_server.php) and [multiple-port server](examples/server/multi_port.php) examples. Server callbacks can use `task()` to dispatch work to task workers and `sendMessage()` for messages between workers.

### Coroutines and coordination

`Swoole\Coroutine\run()` starts a coroutine environment, and `go()` starts a coroutine. `Swoole\Coroutine\Socket` and `Swoole\Coroutine\System` expose I/O operations that cooperate with the scheduler. `Channel` passes values between coroutines; the PHP library also provides `WaitGroup` and `Barrier` for waiting on groups of tasks. Set timeouts for upstream calls and handle cancellation or failures explicitly.

`Swoole\Runtime::enableCoroutine()` hooks selected blocking PHP functions so they can yield inside a coroutine. Depending on the hook flags, build options, and loaded PHP extensions, this can cover streams, files, sleep functions, cURL, and supported database operations. Hooks do not transform arbitrary third-party C library calls. Use the explicit coroutine client or Socket APIs when precise I/O behavior matters.

### HTTP, HTTP/2, and WebSocket

`Swoole\Http\Server` serves HTTP through request callbacks; `Swoole\Coroutine\Http\Server` offers a coroutine-managed server. Request and response APIs cover headers, cookies, uploads, status codes, file delivery, and streamed output. The HTTP/2 implementation supports multiplexed streams, while WebSocket provides upgrade handling and frame encoding and decoding. Compression and TLS depend on the relevant build options and environment.

Coroutine HTTP and HTTP/2 clients call upstream services without occupying a worker while waiting for I/O. For examples and edge cases, see the [HTTP/2 examples](examples/http2/) and [WebSocket tests](tests/swoole_websocket_server/). Applications still need to define their own message formats, authentication, and reconnect behavior.

### Clients, DNS, and asynchronous system operations

Coroutine TCP/UDP clients, HTTP clients, and the lower-level Socket API offer different levels of control over connection setup, timeouts, and message framing. `Swoole\Coroutine\System` provides file and process operations. Optional c-ares integration supports DNS resolution; optional io_uring integration provides additional asynchronous I/O paths on Linux.

For database access, combine the appropriate PHP driver with supported runtime hooks, or use the PHP library's PDO, MySQLi, and Redis connection pools. A pool manages connection reuse; whether an operation yields depends on the driver and hook configuration.

### Processes, threads, and the PHP library

`Swoole\Process` and `Swoole\Process\Pool` manage independent workers. `Swoole\Table` holds structured data shared between processes, and atomic values and messages support coordination. A table is useful for small, frequently accessed state; use a database for persistence or complex queries.

Thread APIs are optional and require a ZTS build of PHP. Use Swoole's thread-safe containers for data shared by threads rather than assuming ordinary PHP variables are safe to share. The bundled `library/src/core/` directory also includes FastCGI, name resolvers, remote objects, connection pools, and other utilities. Available features can differ between Swoole branches.

## Quick start

### Install

Install a released version through PECL:

```bash
pecl install swoole
```

To build the checked-out source, install PHP development tools and a C/C++ compiler, then run:

```bash
phpize
./configure
make -j"$(nproc)"
sudo make install
```

Add `extension=swoole.so` to the `php.ini` used by the PHP CLI and verify with `php --ri swoole`. To load it for one command instead, use `php -d extension=swoole.so --ri swoole`. Run `./configure --help` before enabling optional integrations.

### Start an HTTP server

Save this example as `server.php`:

```php
<?php

$server = new Swoole\Http\Server('127.0.0.1', 9501);
$server->set(['worker_num' => 2]);
$server->on('request', static function ($request, $response): void {
    $response->header('Content-Type', 'text/plain; charset=utf-8');
    $response->end("Hello, Swoole!\n");
});
$server->start();
```

Run `php server.php` in one terminal and `curl http://127.0.0.1:9501/` in another. The server keeps running until you stop it with `Ctrl+C`.

### Run concurrent tasks

Both tasks below wait for 0.1 seconds. While one is waiting, the scheduler can run the other:

```php
<?php

use Swoole\Coroutine\Channel;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

run(function (): void {
    $results = new Channel(2);

    foreach ([1, 2] as $id) {
        go(function () use ($id, $results): void {
            System::sleep(0.1);
            $results->push("task $id done");
        });
    }

    echo $results->pop(), PHP_EOL;
    echo $results->pop(), PHP_EOL;
});
```

## Optional build features

The default build provides the basic server and coroutine APIs. Enable integrations when the required system libraries or PHP extensions are available:

| Configure option | Purpose |
| --- | --- |
| `--enable-sockets` | Integration with the PHP sockets extension |
| `--with-openssl-dir=DIR` | TLS/SSL support |
| `--enable-swoole-curl` | Coroutine cURL support |
| `--enable-swoole-pgsql` | PostgreSQL support |
| `--enable-cares` | c-ares DNS support |
| `--enable-iouring`, `--enable-uring-socket` | Linux io_uring features |
| `--enable-swoole-thread` | Thread support; requires ZTS PHP |

Check `./configure --help` and [`config.m4`](config.m4) for the options and dependencies in your branch. See the [Windows notes](docs/windows-native-support.md) for platform-specific details.

## Documentation and development

- [Official documentation](https://wiki.swoole.com/) covers APIs, configuration, and usage.
- [Examples](examples/) show servers, clients, coroutines, and protocols.
- [Testing guide](docs/TESTS.md) explains PHP PHPT and C++ GoogleTest workflows.
- [Supported versions](docs/SUPPORTED.md) and [changelog](docs/CHANGELOG.md) help with branch selection and upgrades.
- [Repository guidelines](AGENTS.md) describe the source layout, style, tests, and contribution process.

After building the extension, run a focused PHP regression test with:

```bash
PHPT=1 php -n run-tests.php -n -d extension=modules/swoole.so \
  tests/swoole_http_server/create_request_large_upgrade.phpt
```

Report bugs and propose features through [Issues](https://github.com/swoole/swoole-src/issues). Submit code changes through pull requests with relevant tests. Report security issues privately to [team@swoole.com](mailto:team@swoole.com) rather than disclosing them in a public issue.

## License

Swoole is licensed under the [Apache License 2.0](LICENSE).
