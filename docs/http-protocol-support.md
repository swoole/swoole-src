# HTTP protocol support

This document describes HTTP protocol support and implementation limits in Swoole.

## HTTP/1

### Request trailers

Swoole does not support exposing HTTP/1 request trailers to PHP applications.
For chunked requests, Swoole consumes the trailer section to finish parsing the
request, then silently discards its fields. No warning is emitted.

Trailer fields are not added to `Swoole\Http\Request::$header` or
`Swoole\Http\Request::$trailer`; the latter remains `null` for HTTP/1 requests.
They do not participate in Cookie, Content-Type, form, or file-upload processing.
Applications must not rely on HTTP/1 request trailers to supply request metadata.

This behavior applies to `Swoole\Http\Server`, `Swoole\Coroutine\Http\Server`,
and requests parsed through `Swoole\Http\Request::create()->parse()`.

## HTTP/2

### Request trailers

On `master`, HTTP/2 request trailers are available through
`Swoole\Http\Request::$trailer`, separately from the initial request headers.
