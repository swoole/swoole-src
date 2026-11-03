# HTTP protocol support

This document describes HTTP protocol support and implementation limits in Swoole.
Branch-specific descriptions refer to the implementation on each branch, not all
previously released versions.

| Branch | HTTP/1 request trailers | HTTP/2 request trailers |
| --- | --- | --- |
| `master` | Silently discarded | Exposed separately through `Request::$trailer` |
| `6.1`, `6.2` | Silently discarded | Silently discarded; no `Request::$trailer` property is added |

## Multipart form-data uploads

### Reserved part header

`Swoole-Upload-File` is reserved for Swoole's internal upload processing. Clients
must not include this header in any part of a `multipart/form-data` request.
Header names are matched case-insensitively, including when split across reads.

During HTTP/1 upload preprocessing, Swoole rejects a request containing this part
header with `400 Bad Request`, rather than forwarding it to the application.
Client-supplied values are never trusted as paths to uploaded files.

This restriction concerns multipart part headers. A form field named
`Swoole-Upload-File`, or the same text in an uploaded file's contents, does not
constitute this reserved header. Clients should send file metadata through
`Content-Disposition` and the file contents in the part body.

## HTTP/1

### Request trailers

Swoole does not support exposing HTTP/1 request trailers to PHP applications.
For chunked requests, Swoole consumes the trailer section to finish parsing the
request, then silently discards its fields. No warning is emitted.

Trailer fields are not added to `Swoole\Http\Request::$header` and do not
participate in Cookie, Content-Type, form, file-upload, protocol-upgrade, or
response-compression processing. Their presence alone does not cause a
`400 Bad Request` response; normal request-framing validation still applies.
Applications must not rely on HTTP/1 request trailers to supply request metadata.

On `master`, `Swoole\Http\Request::$trailer` remains `null` for HTTP/1 requests.
On `6.1` and `6.2`, this property is not introduced.

This behavior applies to `Swoole\Http\Server`, `Swoole\Coroutine\Http\Server`,
and requests parsed through `Swoole\Http\Request::create()->parse()`.

## HTTP/2

### Request trailers

On `master`, HTTP/2 request trailers are available through
`Swoole\Http\Request::$trailer`, separately from the initial request headers.
They do not replace initial headers or configure request-body parsing.

On `6.1` and `6.2`, HTTP/2 request trailer fields are silently discarded, and no
`Swoole\Http\Request::$trailer` property is introduced. This includes
`Content-Type`, `Cookie`, `Content-Length`, `Accept-Encoding`, pseudo-headers,
and custom fields. They cannot modify the request method, URI, initial headers,
cookies, response compression, or form and file-upload parsing.

Discarded trailer blocks are still HPACK-decoded to preserve the compression
state for subsequent requests on the same connection. When trailers end a
request, the buffered body is parsed using its initial headers before the
application handler runs. These rules also apply to blocks split across
CONTINUATION frames and to empty trailer blocks.

### Initial header processing

On all three branches, HTTP/2 body parsing is configured after the complete
initial header block has been received (`END_HEADERS`). For repeated
`Content-Type` fields, only the last value configures form or multipart parsing.
An earlier value does not initialize a multipart parser or override the final
value's parsing mode.

On `6.1` and `6.2`, processing of `Cookie`, `Content-Length`, and
`Accept-Encoding` is also deferred until the initial header block is complete.
Existing cookie exposure and Content-Length checks are retained; trailer values
do not participate in this processing.
