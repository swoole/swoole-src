# Server sending and synchronous writes

Use `Swoole\Server::send()` for normal application output. It follows the
server's connection-owner routing and output queue. Successful acceptance of a
send does not confirm that the peer application processed the data; applications
that need that guarantee should exchange an application acknowledgement.

## sendwait() restrictions

`sendwait()` performs a synchronous transport write and can block its caller.
At the PHP level, it is limited to BASE mode outside task workers. PROCESS mode
remains unsupported.

On `master`, THREAD mode rejects `sendwait()` with a warning and returns `false`
with `SWOOLE_ERROR_OPERATION_NOT_SUPPORT`. This applies even when the caller is
the connection's event worker: use `send()` consistently in THREAD mode. Native
C++ `Server::sendwait()` also rejects THREAD mode before looking up the
connection, so it cannot borrow another reactor's Socket.

`sendwait()` also returns `false` with `SWOOLE_ERROR_OPERATION_NOT_SUPPORT` if
the connection has pending asynchronous output. It does not drain, discard or
overtake that output. Use `send()` to append further data in order. An allocated
but empty output buffer does not prevent synchronous sending.

Always check the return value. Do not mix direct synchronous writes with pending
`send()` or `sendfile()` operations and assume the new bytes will follow the old
ones. Use a consistent queued sending path when output can encounter backpressure.
