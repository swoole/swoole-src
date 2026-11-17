# Incremental HTTP/2 request bodies

Set `http2_stream_mode => true` before starting an HTTP server to dispatch HTTP/2
requests after their headers, before the peer sends END_STREAM. The option is
false by default. Both `Swoole\Http\Server` with coroutines enabled and
`Swoole\Coroutine\Http\Server` support it. HTTP/1, WebSocket, and ordinary
HTTP/2 servers that leave the option disabled retain buffered request dispatch.

```php
$server->set(['open_http2_protocol' => true, 'http2_stream_mode' => true]);
$handler = function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    while (($data = $request->recv(5)) !== '') {
        if ($data === false) {
            return; // Timeout, cancellation, reset or disconnection.
        }
        $response->write($data);
    }
    $response->trailer('result', 'complete');
    $response->end();
};
// Event server: $server->on('request', $handler);
// Coroutine server: $server->handle('/', $handler);
```

`Request::recv(float $timeout = -1): string|false` returns available body bytes,
an empty string only at clean input EOF, or false for unavailable/failed input.
It requires stream mode and HTTP/2; it does not read HTTP/1 input. Empty DATA and
padding do not count as EOF. One reader may wait per request. The timeout applies
to this read and does not restart on empty frames. Request trailers remain in
`$request->trailer` and are available at EOF. A peer's request half-close does
not end the response half.

In this mode, rawContent/getContent is only the currently buffered body;
automatic form/multipart body parsing is disabled for HTTP/2. Applications that
need a full body must collect it explicitly with their own total size limit.
`package_max_length` limits buffered bytes per stream rather than total bytes
transferred during a long-lived request. Receive stream credit is replenished
when the application consumes data; connection credit continues to let other
streams progress. Reset and connection close wake pending reads and writes.

On `Swoole\Coroutine\Http2\Client`, the same opt-in setting enables send flow
control. Set it before connecting and use a dedicated receiver coroutine to
process SETTINGS/WINDOW_UPDATE while a write is waiting. Existing `send()`,
`write()`, `usePipelineRead`, `recv()` and `pipeline` continue to carry raw HTTP/2
bytes. A returned DATA chunk is not a gRPC message boundary. Keeping a receiver
running is necessary even for client-streamed methods that have no response
messages until request EOF.

The `php-grpc-server-protobuf` PHP library adds message framing, per-message
limits, gzip decoding, final gRPC status and a bounded receiver queue on top of
these general HTTP/2 primitives. It exposes `GRpcServer::serve()` and
`GRpcClient::send/recv/closeSend/close`, and its interface generator maps the
three `.proto` streaming forms to `GRpcStream` input and iterable output.
