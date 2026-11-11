# Connection fields and concurrency boundaries

This document describes the connection close/accept refactor. The TCP acceptor
transfers an unpublished Socket. In PROCESS and THREAD modes, the reactor selected
by `fd % reactor_num` initializes the Connection, updates readiness, and physically
closes the transport. In BASE mode, the accepting worker owns that reactor. PROCESS
reactors run in the master process; THREAD reactors run in event worker threads.

Atomic access requirements depend on every reader, writer, and synchronization
boundary. A single writer does not make concurrent reads safe. Taking a lock only
on the reader side does not synchronize an unlocked writer. `volatile` alone does
not provide synchronization for shared memory between processes.

## Fields immutable within one session

`add_connection()` initializes these ordinary fields before publishing the session.
Retirement and descriptor reuse start a new generation. Workers must validate the
expected session under the slot lock before relying on these values.

| Field | Meaning |
| --- | --- |
| `socket_type` | Protocol type of the listening port |
| `fd` | Transport file descriptor |
| `session_id` | Session generation assigned to this slot |
| `ssl` | Whether a TLS/DTLS instance exists before publication |
| `reactor_id` | Owner reactor; ownership does not migrate within a session |
| `server_fd` | Listening socket associated with the session |
| `local_port` | Local port snapshot |
| `local_addr_index` | Local address index |
| `info` | Peer address snapshot |
| `connect_time` | Connection creation time |

See `Server::add_connection()` in `src/server/master.cc`. Immutability within one
session does not remove the need for generation checks during reuse.
`get_connection_verify*()` is an optimistic lookup; it does not pin the slot's lifetime.

## Ordinary fields owned by the reactor

| Field | Meaning and access path |
| --- | --- |
| `close_queued` | The output queue contains a close marker; close command / output drain |
| `close_reset` | Send RST on physical release; close command / physical close |
| `close_abort` | Discard pending output; close command or transport error / output handling |
| `close_notification_started` | Close notification dispatch has begun; `request_close()` |
| `close_waiting_worker` | Waiting for the worker's CLOSE command; close notification / write event |
| `close_worker_received` | The worker's CLOSE command has reached the owner reactor |
| `recv_paused` | Application explicitly paused receiving; PAUSE/RESUME commands |
| `recv_delayed` | Configured delayed receiving has not been explicitly resumed |
| `recv_throttled` | Input backlog temporarily disabled READ; backpressure timer |
| `recv_shutdown` | Reactor is exiting and accepts no further input |
| `high_watermark` | The owner output queue crossed its high watermark |
| `waiting_time` | Backpressure retry interval |
| `timer` | Backpressure timer, created, cancelled, and fired on the owner reactor |
| `websocket_buffer` | Fragment buffer belonging to the owner protocol parser |
| `object` | HTTP/Redis request object belonging to the owner protocol parser |

Workers request RST or output cancellation through CLOSE command `ext_flags`.
They do not write `close_reset` or `close_abort` directly. These owner fields need
neither individual atomics nor a slot lock on every recv operation.

## Ordinary fields protected by the slot lock

| Field | Participants and synchronization |
| --- | --- |
| `close_actively` | Worker records an active-close claim and selects onClose arguments under the same lock |
| `close_callback_state` | Worker claims and completes one native onClose dispatch call under the lock |
| `connect_callback_claimed` | Worker claims CONNECT dispatch once under the lock |
| `close_worker_started` | Worker records that close processing started; PROCESS receive handling checks under the same lock |
| `close_worker_claimed` | Worker claims the close command; only dispatch failure releases the claim |
| `session_released` | Reactor retires under the lock; other workers read under that lock; owner may read directly |
| `ssl_client_cert` | Worker installs/removes its private certificate object under the lock; snapshot readers use the same lock |
| `ssl_client_cert_pid` | Accessed with the certificate pointer under the lock; another process must not dereference private certificate memory |
| `protect` | Worker protect API, background heartbeat snapshots, and owner idle checks share the lock; owner publishes timeout close_reason before unlocking |

These fields do not require separate atomics. Release the slot lock before calling
PHP, cancelling coroutines, or sending IPC. Never hold it across a user callback;
validate the session again after the callback. `close_callback_state` tracks the
native dispatch call, rather than the lifetime of a yielded PHP coroutine.

## Fields requiring atomic access

| Field | Concurrent access | Implementation |
| --- | --- | --- |
| `lock` | Slot initialization/retirement versus worker generation validation and callback claims | Retain the spinlock |
| `close_reason` | Worker and reactor may report the first close cause concurrently; some reactor writers do not hold the slot lock | First-cause CAS and acquire loads across roles |
| `recv_queued_bytes` | PROCESS reactor adds dispatched bytes while the worker subtracts consumed bytes; the worker lock does not cover reactor increments | Atomic RMW in PROCESS; ordinary arithmetic in BASE/THREAD |
| `last_recv_time` | Reactor writes while background heartbeat and worker queries read | Existing double storage with relaxed atomic accessors; GCC/Clang use no lock or CAS/RMW |

`sw_atomic_t` specifies integer storage. Actual atomicity comes from the operations
used to access it; the typedef does not require every access to be an RMW operation.

`dispatch_task()` uses the existing Factory virtual call. `BaseFactory::dispatch()`
selects `ReceiveQueueMode::OWNER_REACTOR`; `ProcessFactory::dispatch()` selects
`SHARED_PROCESS` and rolls back the counter if IPC dispatch fails. Only RECV_DATA
payload bytes count toward the receive queue; CONNECT certificates and control
payloads do not. C++14 template arguments select the counter policy without a
runtime boolean or an additional counter function pointer.

`prepare_receive_event()` handles PROCESS consumption under the slot lock with
atomic subtraction. `prepare_receive_event_on_reactor()` handles BASE/THREAD with
ordinary subtraction and no slot lock. PROCESS backpressure checks and shared
counter snapshots use `get_recv_queued_bytes()`. The copied snapshot value,
`ClientInfoSnapshot::recv_queued_bytes`, is an ordinary `uint32_t`.

All `last_recv_time` accesses use its getter/setter and the double functions in
`swoole_atomic.h`. The field sits after `lock` in the preserved region. Reuse clears
one prefix between `active` and `lock`, retains the old timestamp, and writes the
actual creation time before publishing the new session. There is no preliminary
zero store. This avoids racing background reads with an ordinary memset and saves
an unnecessary atomic store. The timestamp is an activity snapshot; it does not
publish surrounding metadata. The slot lock validates session, ownership, and protect.

MSVC uses conservative Interlocked operations. GCC/Clang use relaxed load/store;
inspect generated code for the target architecture when assessing their cost.
With GCC x86-64, field reordering reduced `sizeof(Connection)` from 296 through 288
to 280 bytes. Its 52 fields total 278 bytes, leaving two bytes of padding. Given
these field types and eight-byte alignment, 280 bytes is the minimum achievable by
reordering alone. `active` remains at offset zero, frequently accessed fields are
grouped near the front, and the lock/preserved-tail boundary supports one memset.
One million slots save approximately 7.63 MiB compared with the 288-byte layout.
At `-O2`, timestamp access uses an ordinary eight-byte memory operation plus an
integer/SSE register transfer, without LOCK, CAS, or a helper-function call.

## Existing cross-role fields requiring further synchronization work

The following 14 ordinary fields still have cross-role access. Their current types,
a single writer, or a reader-side lock are not sufficient evidence of race freedom.

| Field | Writers / other readers | Boundary requiring further work |
| --- | --- | --- |
| `active` | Reactor publication/retirement / workers and traversal | Publication/retirement hold slot lock and server mutex; generic traversal checks under slot lock; other optimistic lookups still require revalidation |
| `socket` | Reactor assignment/release / some existing API checks | Generic traversal and heartbeat do not dereference it; a raw pointer or atomic pointer does not pin Socket lifetime |
| `worker_id` | Reactor scheduling / worker getClientInfo | Publication of the selected worker snapshot |
| `ssl_ready` | Reactor handshake completion / worker validation, exists/getClientInfo | Publication of handshake completion to workers |
| `overflow` | Reactor output queue / PROCESS worker send-yield checks | Output feedback across processes |
| `uid` | Worker bind API / reactor UID dispatch | Dispatch reads must synchronize with bind writes |
| `websocket_status` | PHP worker handshake/close and reactor protocol paths / both sides | Multiple writers; this is not reactor-private state |
| `websocket_compression` | PHP worker upgrade response / reactor decoding and worker encoding | Upgrade publication/acknowledgement boundary |
| `http_upgrade` | PHP worker upgrade response and reactor protocol selection / reactor parser | Both roles write this flag; upgrade publication must synchronize with parser access |
| `http2_stream` | Reactor protocol detection / PHP worker HTTP and close handling | Protocol detection publication and descriptor reuse |
| `close_errno` | Reactor / worker information queries and onClose | Error-code snapshot |
| `send_queued_bytes` | Reactor / worker and admin queries | Live statistics snapshot |
| `last_send_time` | Reactor / worker and admin queries | Live statistics snapshot |
| `last_dispatch_time` | PROCESS worker / worker and admin queries | Worker writes and getClientInfo hold the slot lock; admin still reads directly |

Relevant code paths:

- `src/server/master.cc`: `add_connection()`, `schedule_worker()`,
  `is_healthy_connection()`, and `get_client_info()`.
- `src/server/reactor_thread.cc`: TLS handshake, output events, heartbeat handling,
  protocol dispatch, and physical release.
- `src/server/process.cc`: PROCESS worker output feedback.
- `ext-src/swoole_server.cc`: `bind()`, `protect()`, `exists()`, and onClose.
- `ext-src/swoole_http_request.cc`, `swoole_http_response.cc`,
  `swoole_websocket_server.cc`, `src/server/port.cc`, and
  `src/protocol/websocket.cc`: protocol state shared by workers and reactors.

These fields need explicit IPC/protocol snapshot semantics. Removing atomics or
locking only readers does not establish safety. An atomic Socket, certificate, or
parser pointer makes access to the pointer atomic, but does not keep its object alive.

## Connection predicates

`is_ssl_ready()` accepts a plain connection or a TLS connection with a completed
handshake. Its negation identifies a TLS connection still awaiting readiness.

`is_websocket_status()` matches one exact status. `is_websocket_active()` strictly
matches ACTIVE. `is_websocket_status_at_least()` preserves the existing ordered
comparisons: CLOSING and HANDSHAKE_FAILED have values greater than ACTIVE. Callers
that previously used an ACTIVE threshold retain that boundary.

These predicates encapsulate existing checks. They do not add synchronization or
change the requirements for reactor ownership, slot locking, or session validation.

## Heartbeat traversal and force close

The dedicated PROCESS heartbeat thread scans the connection range and selects
timeout candidates. A full scan must stay off the I/O reactors: traversing a million
slots can otherwise monopolize their event loops. The background scan first loads
`last_recv_time` with relaxed ordering and skips recent activity using the shortest
enabled idle timeout across all ports. Only possible expirations acquire the slot
lock to check active/session/owner/listener/protect and copy session_id/reactor_id.
The background thread neither dereferences connection Sockets nor modifies owner
close state. It releases the slot lock before sending IPC.

Each candidate travels through a dedicated pipe as `SW_SERVER_EVENT_CLOSE_FORCE`
with its session_id. The existing reactor startup barrier publishes every pipe
before the heartbeat thread starts. These pipes are separate from worker traffic.
The heartbeat thread exclusively owns the write endpoint and uses `send_sync()`;
a full pipe waits for writable readiness and retries. Timeouts or other send failures
are logged.

The owner reactor checks only the received candidate. It revalidates generation,
ownership, current receive time, and protect, handling activity, protection changes,
and descriptor reuse while the request was queued. Traversal cost remains on the
background thread; reactor work scales with timeout requests. A pipe callback handles
at most 64 heartbeat close requests before yielding. Level-triggered readiness
schedules the remaining datagrams again.

A condition variable interrupts the periodic wait during shutdown; the scanner also
checks the stop flag between candidates. An in-flight `send_sync()` follows the
Socket write timeout. Both threads must be joined before destroying the pipe.
BASE, THREAD, and PROCESS single_thread retain their reactor timer mode.

`foreach_connection_on_reactor()` selects slots by fd ownership before accessing
mutable Connection state. `is_valid_connection()` checks active without reading
Socket or fd_type. Event handlers still compare `conn->socket == event->socket`
to reject stale events. Generic `foreach_connection()` supplies candidate slots;
callers must validate the session under the slot lock before cross-role access.
It invokes callbacks without holding the lock and does not pin Socket lifetime.

For a connection requiring worker notification, the first force-close request
reuses `close_abort`, `close_notification_started`, and `close_waiting_worker` to
stop readiness, mark output for cancellation, and notify the worker once.
If that worker is busy and has not completed native onClose
dispatch, a subsequent force request shuts down transport I/O and releases pending
output while retaining the fd/session for the late callback. The descriptor cannot
be reused in that interval.

Connections with notifications disabled, an incomplete TLS handshake, or a worker
CLOSE command already received by the owner can be released directly.

Physical retirement follows completed callback dispatch or an idle duration beyond
`heartbeat_idle_time + max_wait_time + 2 * heartbeat_check_interval`. The latter is
a resource-reclamation fallback for a dead or permanently blocked worker; callback
delivery cannot be guaranteed in that case. Callback claims remain at most once,
and stale-session commands cannot affect a replacement connection. No additional
Connection state flag is required for this policy.

The same server mutex serializes active publication with min/max fd updates and
active retirement with max fd shrinkage. This prevents one reactor from shrinking
bounds past a slot that another reactor is still publishing. When both locks are
needed, acquire the server mutex before the slot lock. The owner removes reactor
interest before acquiring either lock. Retirement releases the slot lock before
scanning for the new max fd under the server mutex. Other workers can inspect the
retired slot during the scan, and a publisher waiting for the mutex holds no slot
lock. Cross-process generation validation still requires the shared slot lock.

The added locks cover accept/close, idle checks, and queries. They do not add slot
locks to the normal recv/send paths.

## Late CLOSE cleanup in the worker

The worker claims onClose and captures its listener/reactor/protocol context in
one slot-locked operation. PHP dispatch uses that captured context, so retirement
between the claim and callback entry does not silently skip an already claimed
callback. Cancelling send-yield coroutines can reenter close. The callback claim
still prevents a second user callback.

A CLOSE received after hard-deadline retirement uses the internal
`cleanup_connection` callback, keyed by the old session ID. It cancels suspended
senders and releases HTTP/HTTP2 state without accessing a replacement connection or
claiming a new user callback. Hard-deadline reclamation still cannot guarantee
delivery of a callback that was never claimed before the session was retired.

Certificate ownership stays with the allocating worker. Normal CLOSE handling
releases the certificate, and worker process exit leaves private memory to the
operating system. Connection reuse clears the old certificate alias.

A full kernel datagram queue can defer the CLOSE write to the worker's async
output buffer. A failed submission releases the command claim while preserving
the callback claim. No background retry is scheduled.

An explicitly paused socket with no pending output is removed from polling.
EOF and HUP can be observed once receiving resumes. Pending output keeps its
WRITE interest.

Pause removes every read-side event, including EOF and HUP, on purpose. Keeping
only EOF/HUP interest would depend on epoll's `EPOLLRDHUP`/`EPOLLHUP`; kqueue, poll
and iocp have different semantics, so the reactor API exposes no such partial
interest. A peer that disconnects while its socket is paused is therefore not
noticed until receiving resumes or the heartbeat reclaims the session. Servers
that pause connections for long periods must configure `heartbeat_idle_time`
(or `max_idle_time`); otherwise a dead peer keeps its session until resume.
The same applies to throttled and delayed receiving.

`abort_count` counts failures before a session is published. A failure after
publication retires the session and contributes to `close_count`, balancing
the increment already recorded in `accept_count`.
