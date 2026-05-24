# Windows IOCP cURL Runtime Design

This document describes the Windows IOCP implementation strategy for Swoole's native cURL coroutine runtime.

The short version is:

- The implementation does not replace libcurl's network I/O engine.
- libcurl still owns the transfer state machine and performs the actual socket reads and writes.
- Swoole uses Windows overlapped I/O and IOCP as a readiness bridge, so the coroutine scheduler can wait without blocking a thread.
- The current bridge submits zero-byte Winsock operations to receive IOCP completions and then calls back into `curl_multi_socket_action()`.

This is technically valid as a readiness adapter, but it must be understood as a bridge from a completion-based API to libcurl's readiness-based multi-socket API. It is not the same as a full data-path IOCP transport where Swoole reads response bytes and passes them into libcurl.

## Background

libcurl's `curl_multi_socket_action()` API is readiness based. With `CURLMOPT_SOCKETFUNCTION`, libcurl tells the application which socket should be monitored and for which condition:

- `CURL_POLL_IN`
- `CURL_POLL_OUT`
- `CURL_POLL_INOUT`
- `CURL_POLL_REMOVE`

The application must then notify libcurl when the requested activity happens by calling:

```c
curl_multi_socket_action(multi, sockfd, event_bitmask, &running_handles);
```

On Linux this maps naturally to `epoll`, `poll`, or another readiness API. On Windows, IOCP is different: it reports completion of submitted operations. It does not directly report "this socket is readable" or "this socket is writable" unless the application first submits an overlapped operation that can complete.

Therefore, the Windows implementation needs an adapter.

## Design Goal

The design goal is to keep the existing Swoole cURL integration intact:

- Keep using libcurl's multi socket API.
- Keep the existing `Multi`, `Handle`, selector, timer, and coroutine wake-up flow.
- Avoid implementing a parallel HTTP/TLS/proxy/protocol stack.
- Avoid intercepting libcurl's internal payload reads and writes.
- Use the existing Swoole IOCP reactor integration for coroutine scheduling on Windows.

The Windows-specific code should only replace the readiness waiting backend.

## High-Level Flow

The existing cURL flow remains:

1. `curl_multi_add_handle()` adds an easy handle to a Swoole `Multi`.
2. libcurl invokes `CURLMOPT_SOCKETFUNCTION` when it wants socket activity.
3. Swoole records the requested action for that socket.
4. Swoole waits for either a timer or a socket activity signal.
5. When activity is observed, Swoole resumes the bound coroutine.
6. `selector_finish()` calls `curl_multi_socket_action()`.
7. libcurl performs the actual socket I/O internally.
8. libcurl updates transfer state and may request new socket events.

On Windows, step 4 is backed by IOCP probes instead of by adding the socket to a poll reactor.

## IOCP Readiness Bridge

IOCP is completion oriented. To receive a completion packet, Swoole posts an overlapped Winsock operation.

For each libcurl socket, Swoole keeps at most:

- one pending read probe
- one pending write probe

The operation object is `IocpOperation`. It embeds an `IocpEvent`, which is handled by the shared Swoole IOCP dispatcher.

The probe buffers are zero length:

```c++
WSABUF buffer;
buffer.buf = &dummy;
buffer.len = 0;
```

For read interest, Swoole submits:

```c++
WSARecv(sockfd, &buffer, 1, &bytes, &flags, &overlapped, nullptr);
```

For write interest, Swoole submits:

```c++
WSASend(sockfd, &buffer, 1, &bytes, 0, &overlapped, nullptr);
```

When the completion packet is received, the IOCP dispatcher calls the cURL operation callback. That callback does not consume payload data. It only records the corresponding libcurl event bit:

- `CURL_CSELECT_IN`
- `CURL_CSELECT_OUT`
- `CURL_CSELECT_ERR`

Then it uses the existing `Multi::callback()` path to resume the coroutine. The subsequent `curl_multi_socket_action()` call lets libcurl perform the real transfer I/O.

## Why Zero-Byte Operations Do Not Corrupt cURL Data

The zero-byte probe does not provide a payload buffer to Winsock. Its purpose is to turn a Winsock completion into a signal that the socket should be revisited, or that the socket has transitioned to an error/close state.

Because no payload bytes are read into a Swoole buffer, there is no duplicated receive path and no data that must be copied back into libcurl. After Swoole wakes libcurl, libcurl still calls `recv()`, `send()`, `WSARecv()`, `WSASend()`, or its own socket abstraction internally, depending on how libcurl was built.

This is important because libcurl owns:

- TLS state
- HTTP/1.1 and HTTP/2 state
- proxy negotiation
- redirects and authentication
- upload and download callbacks
- connection reuse
- error mapping

Swoole should not read application payload bytes unless libcurl provides an API to accept externally completed reads. The public multi-socket API does not work that way.

## Read-Side Reliability

The read-side probe is the stronger part of this design.

A zero-byte overlapped receive is a common Windows technique for converting completion notification into a readability signal. The completion tells the application that the socket should be revisited. Swoole then wakes libcurl and lets libcurl drain whatever data is actually available.

The implementation relies on this Winsock behavior, but it still treats the completion only as a readiness hint. The actual amount of readable data is not inferred from the zero-byte completion result.

Important properties:

- It does not consume response bytes.
- It detects readable progress and close/error transitions.
- It avoids polling the socket from the coroutine loop.
- It must be rearmed after libcurl processes the socket and requests more read interest.

The implementation avoids duplicate read probes by keeping `Socket::read_operation`. If a read probe is already pending, another one is not submitted.

## Write-Side Reliability

The write-side probe is more subtle.

For libcurl, `CURL_POLL_OUT` means "tell me when I should try writing again." On readiness APIs this usually means the socket send buffer has capacity. With IOCP, a zero-byte `WSASend()` completion is only a completion signal for a submitted zero-byte operation. It is not a perfect equivalent of readiness back-pressure.

This can still be correct because libcurl is allowed to receive spurious readiness notifications. If libcurl tries to write and the socket cannot accept data, libcurl keeps the transfer pending and asks for write interest again.

However, it can be inefficient if zero-byte sends complete too eagerly while the real send buffer is still full. In that case Swoole could wake libcurl repeatedly, libcurl could attempt a real send, receive `WSAEWOULDBLOCK`, and ask for write interest again. The result would be a busy loop under high upload pressure or with a saturated peer.

Mitigations in the current design:

- Only one pending write probe is allowed per socket.
- The write probe is cancelled when libcurl changes interest to read-only.
- libcurl remains the authority on whether progress was actually made.
- The coroutine is resumed through the existing deferred callback path, which coalesces same-tick wake-ups.

Remaining risk:

- Zero-byte `WSASend()` is a wake-up hint, not a strong write-capacity guarantee.
- Heavy upload workloads need stress testing.
- If busy wake-ups are observed, the write side should be changed to a stronger Windows readiness source.

Recommended fallback if this becomes an issue:

- Use `WSAPoll()` or `select()` only for `CURL_POLL_OUT` readiness while keeping IOCP for read-side wake-ups.
- Or use `WSAEventSelect()` for writable notifications and bridge the event into the Swoole reactor.
- Or provide a libcurl socket creation hook to ensure all sockets are created with the exact overlapped/event flags needed by a dedicated Windows backend.

## Socket Creation Requirements

The socket must support overlapped I/O before it can be associated with an IOCP and used with overlapped `WSARecv()` or `WSASend()`.

On Windows Sockets 2:

- sockets created with `socket()` have the overlapped attribute by default
- sockets created with `WSASocket()` need `WSA_FLAG_OVERLAPPED`

libcurl normally creates sockets internally. If a future libcurl build or option creates sockets without the overlapped attribute, IOCP association or overlapped probes can fail. In that case Swoole should install a `CURLOPT_OPENSOCKETFUNCTION` hook, or an equivalent central socket creation hook, to force overlapped-capable sockets.

## Timers

libcurl's multi-socket API also requires timer handling. The implementation keeps the existing `CURLMOPT_TIMERFUNCTION` path:

1. libcurl reports a timeout.
2. Swoole arms a Swoole timer.
3. The timer callback marks `selector.timer_callback`.
4. `selector_finish()` calls:

```c
curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &running_handles);
```

This remains the same on Windows.

## Cancellation and Lifetime

Each pending IOCP probe owns an `OVERLAPPED` object through `IocpOperation`. The operation must remain alive until one of these happens:

- the IOCP completion is dequeued and processed
- submission fails synchronously before the operation becomes pending

When libcurl removes a socket, Swoole:

1. erases it from the `sockets` map
2. clears libcurl's socket assignment with `curl_multi_assign(..., nullptr)`
3. marks the Swoole cURL socket as deleted
4. cancels pending probes with `CancelIoEx()`
5. releases the socket object only after all pending probes have completed or have failed synchronously

The completion callback checks the deleted/orphaned state before waking libcurl. This prevents a cancelled probe from re-entering libcurl after libcurl has already removed the socket.

## Error Handling

If a probe completes with an error, Swoole reports `CURL_CSELECT_ERR` to libcurl.

libcurl then performs its own socket checks and maps the transfer result. This keeps error ownership in libcurl and avoids duplicating protocol-specific error handling in Swoole.

If a probe submission fails synchronously with anything other than `WSA_IO_PENDING`, Swoole cancels the local IOCP submission bookkeeping, sets the Windows socket error, and reports failure to the caller.

## Correctness Model

This implementation is correct if the following assumptions hold:

- libcurl tolerates spurious socket readiness notifications.
- The socket supports overlapped I/O.
- Each pending probe object remains alive until completion.
- Cancelled probes do not call back into libcurl after socket removal.
- Timers are still delivered to `curl_multi_socket_action()`.
- The write-side probe does not create unacceptable busy wake-ups under expected workloads.

The first five are correctness requirements. The last one is primarily a performance and scheduling fairness requirement.

## What This Implementation Is Not

This is not a full IOCP cURL transport.

A full data-path IOCP transport would require libcurl itself to submit overlapped receives and sends, or a lower-level socket provider that lets libcurl consume externally completed I/O. The public `curl_multi_socket_action()` API does not expose such a data injection path.

Therefore, Swoole should not try to read HTTP response bytes in IOCP callbacks and then pass them to libcurl. That would duplicate libcurl's socket ownership and break TLS/protocol state.

## Operational Guidance

The implementation should be validated with:

- HTTP download tests
- HTTPS download tests
- concurrent multi-handle downloads
- large uploads
- slow receiver tests
- connection reset tests
- timeout tests
- cancellation tests
- connection reuse tests

Pay special attention to large upload and slow peer cases. Those are the workloads most likely to expose excessive write wake-ups from zero-byte `WSASend()` probes.

## References

- libcurl `CURLMOPT_SOCKETFUNCTION`: https://curl.se/libcurl/c/CURLMOPT_SOCKETFUNCTION.html
- libcurl multi socket drive model: https://everything.curl.dev/transfers/drive/multi-socket.html
- Microsoft `WSARecv`: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv
- Microsoft `WSASend`: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend
- Microsoft I/O Completion Ports: https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports
- Microsoft `GetQueuedCompletionStatus`: https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus
- Microsoft overlapped socket attribute: https://learn.microsoft.com/en-us/windows/win32/winsock/default-state-for-a-socket-s-overlapped-attribute-2
