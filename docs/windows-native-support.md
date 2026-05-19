# Native Windows Support Matrix

This document describes the module support status of the native Windows build
of Swoole. It covers the Win32/IOCP port built by `config.w32`; it does not
describe Cygwin, WSL, or POSIX compatibility layers.

The matrix is based on the current Windows build configuration and module
registration code. Some optional modules are available only when their build
flags and third-party dependencies are enabled.

## Support Levels

- **Supported**: registered and intended to work on native Windows.
- **Limited**: registered, but some APIs are unavailable because they depend on
  POSIX-only primitives.
- **Optional**: available only when the corresponding `config.w32` option and
  dependency are enabled.
- **Unsupported**: not registered on native Windows, or not usable because the
  required operating system primitive does not exist on Windows.

## Windows Runtime Foundation

Native Windows Swoole uses Windows APIs instead of emulating the Linux reactor
stack:

- Coroutine socket I/O is backed by IOCP.
- Windows socket support is based on Winsock.
- Timers are implemented on top of Windows timer facilities.
- Windows-specific filesystem and path handling is used where required.
- Optional coroutine hooks are enabled according to build flags and available
  dependencies.

The following POSIX primitives are not available on native Windows and are not
provided by the native port:

- `fork`
- Unix domain sockets
- POSIX signals
- POSIX message queues
- POSIX process manager semantics
- POSIX file descriptor reactor semantics

## Supported Modules

### Core

The core extension entry points and base classes are supported:

- `Swoole\Exception`
- `Swoole\Error`
- Core global functions such as version, CPU count, logging, error handling,
  MIME helpers, DNS/name resolver helpers, and local network information
  helpers
- Core constants that are meaningful on Windows

POSIX-specific helper functions are not available or not meaningful on native
Windows. See [Unsupported Modules and APIs](#unsupported-modules-and-apis).

### Timer

The timer module is supported:

- `Swoole\Timer`
- `Swoole\Timer\Iterator`

### Coroutine

The coroutine runtime is supported on native Windows:

- `Swoole\Coroutine`
- `Swoole\Coroutine\Scheduler`
- `Swoole\Coroutine\Channel`
- `Swoole\Coroutine\Lock`
- `Swoole\Coroutine\System`
- `Swoole\Coroutine\Socket`

`Swoole\Coroutine\System` is limited by the absence of POSIX process and signal
features. File, sleep, DNS, and other Windows-compatible coroutine operations
are the intended supported surface.

### Coroutine Clients

The coroutine client modules are supported:

- `Swoole\Coroutine\Client`
- `Swoole\Coroutine\Http\Client`
- `Swoole\Coroutine\Http2\Client`

These clients are the recommended replacement for `Swoole\Client` and
`Swoole\Async\Client` on native Windows.

### Coroutine HTTP Server

The coroutine HTTP server is supported:

- `Swoole\Coroutine\Http\Server`

This is the recommended server-side programming model on native Windows. It is
single-process and coroutine-based; it is not the same module as the classic
asynchronous `Swoole\Http\Server`.

### HTTP and WebSocket Helper Objects

The following HTTP and WebSocket helper classes are supported:

- `Swoole\Http\Request`
- `Swoole\Http\Response`
- `Swoole\Http\Cookie`
- `Swoole\WebSocket\Frame`
- `Swoole\WebSocket\CloseFrame`

`Swoole\WebSocket\Server` is not supported on native Windows. The frame classes
remain available for protocol handling and helper APIs.

### Name Resolver

The coroutine name resolver module is supported:

- `Swoole\NameResolver`

### Runtime Hooks

Coroutine runtime hooks are supported for Windows-compatible operations and
enabled according to the build configuration:

- TCP and UDP socket operations
- SSL/TLS socket operations when OpenSSL support is enabled
- File operations supported by the Windows coroutine backend
- cURL hooks when cURL hook support is enabled

Hooks that depend on POSIX process, signal, Unix socket, or Linux-only reactor
primitives are not available on native Windows.

### Event and Reactor APIs

The public event API is available with native Windows limitations:

- `Swoole\Event`
- Public event-loop add/delete/set/write/defer/cycle APIs for supported
  Winsock sockets
- `Swoole\Event::wait()` as an explicit entry point for the Windows event loop

The Windows reactor backend is implemented with IOCP and AFD readiness polling.
It is intended to provide readiness notifications for Winsock sockets, similar
to the Linux `poll`/`epoll` surface used by Swoole's existing event API.

This is not a full POSIX reactor compatibility layer. POSIX file descriptors,
Unix sockets, process pipes, signals, and Linux-specific descriptors such as
eventfd, signalfd, and timerfd are not supported by `Swoole\Event` on native
Windows.

## Optional Modules

### Native cURL Hook

The cURL hook is optional:

- Build option: `--enable-swoole-curl`
- Module: coroutine/runtime integration for cURL

When enabled, the Windows implementation should use the native Windows async
mechanism provided by libcurl and the Swoole Windows backend, rather than the
Linux `epoll`/`poll` reactor path.

### Thread Module

The thread module is optional and requires a PHP ZTS build:

- Build option: `--enable-swoole-thread`
- `Swoole\Thread`
- `Swoole\Thread\Atomic`
- `Swoole\Thread\Atomic\Long`
- `Swoole\Thread\Lock`
- `Swoole\Thread\Barrier`
- `Swoole\Thread\Queue`
- `Swoole\Thread\Map`
- `Swoole\Thread\ArrayList`
- `Swoole\Thread\Error`

Thread support does not turn the IOCP backend into a multi-threaded connection
balancer. Each PHP thread must be treated as owning its own runtime context
unless an API explicitly documents that sharing is supported.

### Standard Extension Helpers

The standard extension helper module is optional:

- Build option: `--enable-swoole-stdext`

### Database Coroutine Clients

Database coroutine clients are optional and depend on both build flags and
third-party client libraries:

- PostgreSQL coroutine client: `--enable-swoole-pgsql`
- SQLite coroutine client: `--enable-swoole-sqlite`
- ODBC coroutine client: `--enable-swoole-odbc`
- Oracle coroutine client: enabled when Oracle client support is configured
- Firebird coroutine client: `--with-swoole-firebird`

Only the modules that are enabled and successfully linked during the Windows
build are available at runtime.

### Other Optional Protocol Integrations

The following integrations are optional and dependency-dependent:

- SSH2 integration: `--with-swoole-ssh2`
- FTP integration: `--enable-swoole-ftp`

## Unsupported Modules and APIs

### Classic Asynchronous Server Modules

The classic asynchronous server family is not supported on native Windows:

- `Swoole\Server`
- `Swoole\Server\Port`
- `Swoole\Http\Server`
- `Swoole\WebSocket\Server`
- `Swoole\Redis\Server`
- Server task workers
- Server process workers
- Server manager process
- Server event classes and packet/task helper classes that belong to the
  classic server implementation

Use `Swoole\Coroutine\Http\Server`, coroutine clients, and coroutine sockets
instead.

### Process Modules

The process modules are not supported:

- `Swoole\Process`
- `Swoole\Process\Pool`
- POSIX-style process manager APIs
- `fork`-based worker models
- Signal-based process control

Windows applications should use the coroutine runtime, the optional thread
module, PHP's Windows-compatible process APIs, or the Windows service model,
depending on the use case.

### Multi-Process Shared Memory Utility Classes

The following classes and helpers are not supported on native Windows:

- `Swoole\Atomic`
- `Swoole\Atomic\Long`
- `Swoole\Lock`
- `Swoole\Table`
- `swoole_table()`

These APIs are designed primarily for Swoole's multi-process programming model.
Native Windows Swoole does not provide that process model, so these classes are
not registered and their binding sources are excluded from the Windows build.
The `swoole_table()` helper is also not declared on Windows because it depends
on `Swoole\Table`.

Use the optional thread module for native Windows shared-state coordination:

- `Swoole\Thread\Atomic`
- `Swoole\Thread\Atomic\Long`
- `Swoole\Thread\Lock`
- `Swoole\Thread\Queue`
- `Swoole\Thread\Map`
- `Swoole\Thread\ArrayList`

### Non-Coroutine Client Modules

The classic client modules are not supported:

- `Swoole\Client`
- `Swoole\Async\Client`

Use the coroutine client modules instead:

- `Swoole\Coroutine\Client`
- `Swoole\Coroutine\Socket`
- `Swoole\Coroutine\Http\Client`
- `Swoole\Coroutine\Http2\Client`

### Unix Socket, Pipe, and Message Queue APIs

The following IPC facilities are not supported:

- Unix stream sockets
- Unix datagram sockets
- Unix socket files
- POSIX pipes exposed through Swoole process APIs
- POSIX message queues

Some socket constants may still be visible for source compatibility, but the
underlying feature is not usable on native Windows.

### Signal APIs

POSIX signal APIs are not supported:

- Signal registration
- Signal dispatch integration
- Coroutine signal waiting
- Signal-based process control

Windows does not provide POSIX signal semantics, so code that depends on them
must be redesigned for Windows.

### Linux-Specific Backends

Linux-only backends and features are not supported:

- `epoll`
- `io_uring`
- Linux eventfd/signalfd/timerfd based integrations
- Linux process and socket options that have no Winsock equivalent

## Migration Guide

Use the following replacements when porting Swoole applications to native
Windows:

| Linux/POSIX-oriented API | Native Windows replacement |
| --- | --- |
| `Swoole\Http\Server` | `Swoole\Coroutine\Http\Server` |
| `Swoole\WebSocket\Server` | Coroutine HTTP server plus WebSocket frame helpers where applicable |
| `Swoole\Server` | Coroutine sockets, coroutine clients, or an application-specific Windows service model |
| `Swoole\Client` | `Swoole\Coroutine\Client` |
| `Swoole\Async\Client` | `Swoole\Coroutine\Client` or `Swoole\Coroutine\Socket` |
| `Swoole\Event` | Native Windows `Swoole\Event` for supported Winsock sockets, or coroutine scheduling and supported runtime hooks |
| `Swoole\Process` / `Swoole\Process\Pool` | Optional `Swoole\Thread`, PHP Windows process APIs, or Windows services |
| `Swoole\Atomic` / `Swoole\Atomic\Long` | Optional `Swoole\Thread\Atomic` / `Swoole\Thread\Atomic\Long` |
| `Swoole\Lock` | Optional `Swoole\Thread\Lock` or coroutine synchronization primitives |
| `Swoole\Table` / `swoole_table()` | Optional `Swoole\Thread\Map`, `Swoole\Thread\ArrayList`, or application-managed storage |
| Unix sockets / POSIX IPC | TCP loopback, named pipes outside Swoole, or Windows-native IPC |
| Signals | Windows control handlers, service control callbacks, or explicit application messages |

## Build Notes

The native Windows build is configured through `config.w32`.

Important build characteristics:

- `SW_USE_IOCP` enables the Windows IOCP backend.
- `SW_USE_IOCP_SOCKET` enables IOCP-backed coroutine socket support.
- The Windows reactor source is compiled as a separate implementation unit and
  uses AFD readiness polling on top of IOCP for `Swoole\Event`.
- OpenSSL, zlib, brotli, zstd, nghttp2, c-ares, and other dependencies are
  enabled only when found and configured for the Windows build.
- Optional Swoole modules must be explicitly enabled through their Windows build
  options.
- The thread module requires PHP ZTS.

When documenting or testing Windows support, always distinguish between a class
being compiled into the extension and a feature being semantically available on
Windows. Some constants and helper declarations may exist for compatibility even
when the related POSIX feature is unsupported.
