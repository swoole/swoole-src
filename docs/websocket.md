# WebSocket usage and boundaries

This document collects WebSocket usage details and boundary behavior, including
upgrade timing, sending and application completion before closing. Implementation
details below describe `master`; check the behavior of the release in use.

## Sending after the HTTP upgrade

A TCP connection is not yet an established WebSocket connection while the HTTP
upgrade is pending. On `Swoole\WebSocket\Server`, `push()`, `ping()` and
`disconnect()` reject connections that are still handshaking, have failed the
handshake or are closing. `isEstablished()` reports false for these states.

With the default handshake, send initial application messages from `onOpen`.
For a custom handshake, finish the successful HTTP upgrade response first, then
schedule initial sends with `Swoole\Event::defer()`. Do not send WebSocket frames
while constructing the upgrade response, including from header value conversion
code. Frames must follow the HTTP upgrade response on the wire.

`isEstablished()` is a local state check, not confirmation that the peer has
received the upgrade response or a guarantee that a subsequent send will succeed.
Always check the send result.

## Closing after application work completes

When the peer must finish processing messages before a connection closes, agree
on completion through ordinary WebSocket application messages first. Then close
the WebSocket connection. Define this exchange in the application's message
protocol; a WebSocket Close frame alone does not confirm business completion.

### Recommended sequence

1. Stop starting new work for the connection and coordinate its writers so that
   all final application messages are submitted before the completion request.
2. Send a completion request with an identifier, such as
   `{"type":"finish","id":"job-42"}`.
3. The peer finishes the work covered by that identifier and sends a matching
   acknowledgement, such as `{"type":"finish_ack","id":"job-42"}`. It keeps
   the connection open for the initiator to close.
4. The initiator receives and validates the acknowledgement, then initiates
   WebSocket closure. For `Swoole\WebSocket\Server`, use
   `$server->disconnect($fd, 1000, 'completed')` and check its return value.
5. Release connection resources when closure completes. If the acknowledgement
   does not arrive within the application's deadline, terminate the connection
   and record the operation as unconfirmed.

For example:

```text
Initiator                              Peer
    | ---- final application data ----> |
    | ---- finish(job-42) ------------> |
    |                                  | finish processing job-42
    | <--- finish_ack(job-42) ---------- |
    | ---- initiate WebSocket close --> |
```

The acknowledgement must describe the guarantee the application needs. If
completion means a database transaction was committed, send the acknowledgement
after that commit, rather than merely after receiving the message. Applications
that process messages concurrently must explicitly wait for the relevant work;
receiving the completion request does not itself mean earlier tasks have finished.

### What sending and closing confirm

A successful `push()` can mean that data was accepted into a local output queue.
It does not prove that the peer received the message or processed it. Likewise,
`onClose` reports local connection closure, not confirmation of remote business
completion.

WebSocket Close frames terminate the protocol session. They are not application
acknowledgements. Do not put essential final business data only in the Close
reason, or use `push($fd, $lastMessage)` followed immediately by transport closure
as proof that the peer processed `$lastMessage`. Sending a Close frame through
`push()` is also not equivalent to calling `disconnect()`.

`Swoole\WebSocket\Server::disconnect()` sends a Close frame and initiates
connection closure; it does not wait for an application acknowledgement. Perform
the completion exchange before calling it. Use the appropriate close API for
other WebSocket server or client types, and handle send and close failures.

An application acknowledgement reduces dependence on the delivery of final
messages during connection shutdown. It does not change Swoole's output queue
or Close-frame handling, and cannot guarantee a clean protocol shutdown after
a network failure. If the connection breaks before the acknowledgement arrives,
the outcome is unknown: the peer may already have completed the work. Use stable
operation identifiers and idempotent retries or a status query when recovery is
required. A fixed sleep before closing is not a substitute for an acknowledgement.
