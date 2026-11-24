# Server event dispatch

This document describes the behavior on `master`, introduced in
[16d3d15a7](https://github.com/swoole/swoole-src/commit/16d3d15a798f2e2de32584a66632dd9d52d892e3).
It applies to `Swoole\Server` and its HTTP and WebSocket subclasses in BASE,
PROCESS and THREAD modes.

## Top-level event loop guarantee

**`onClose` and `onBufferFull` are always dispatched from the top level of the
worker's event loop.** They do not run as nested PHP callbacks inside the
`send()`, `close()` or response operation that generated the event.

| Event | Dispatch behavior |
| --- | --- |
| `onClose` for an active close, including `Server::close()` | Queued as an event-loop defer task. |
| `onClose` for a passive close, such as a peer disconnect | Dispatched directly from the event-loop notification. |
| `onBufferFull` | Always queued as an event-loop defer task. |
| User `onBufferEmpty` callback | Also queued as an event-loop defer task to preserve buffer notification order. |

A deferred callback can start once the current PHP execution returns or yields
control to the event loop. An application coroutine can still be suspended when
the event is dispatched; the guarantee does not require every application
coroutine to finish first.

## Closing a connection

`Server::close()` initiates the close immediately. Its `onClose` callback runs
later, from the event loop. Code following `close()` in the current uninterrupted
PHP execution runs before that callback.

For example, with these callbacks:

```php
$server->on('Receive', function (Swoole\Server $server, int $fd) {
    echo "receive:start\n";
    $server->close($fd);
    echo "receive:end\n";
});

$server->on('Close', function () {
    echo "close\n";
});
```

The output is:

```text
receive:start
receive:end
close
```

The same dispatch rule applies when a response operation actively closes its
connection after a send failure. If the operation throws a coroutine
cancellation exception, the current PHP execution can catch it before a deferred
`onClose` callback starts. This preserves the operation's exception delivery.

## Buffer notifications

Crossing the output buffer's high watermark queues `onBufferFull`. It runs from
the event loop after the current PHP execution gives control back to the loop,
including when a `send()` call triggered the notification.

User `onBufferFull` and `onBufferEmpty` callbacks are queued in notification
order, so deferring Full does not allow its corresponding Empty callback to
overtake it. Internal send-yield coroutine wakeups still happen when the buffer
empty notification is processed.

## Coroutine behavior

`onClose` continues to follow `enable_coroutine`. With coroutines enabled, its
callback coroutine is created from the top-level event loop. With coroutines
disabled, the callback runs directly at that dispatch point.

`onBufferFull` and `onBufferEmpty` callbacks run without an automatically created
coroutine. Deferring these events does not change their coroutine behavior.
