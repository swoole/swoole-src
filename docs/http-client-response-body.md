# Coroutine HTTP client response bodies

This document describes response body handling by
`Swoole\Coroutine\Http\Client` on `master`.

## Automatic decompression

With `body_decompression=true` (the default), the client automatically decodes a
single supported `Content-Encoding`. Depending on the extension's build options,
supported codings are `gzip`, `deflate`, `br` and `zstd`. Coding names are matched
in full and case-insensitively. An unknown or unavailable single coding is left
unchanged; inspect the response headers if the application needs to handle it.

**Automatic decompression does not support multiple content codings.** For
example, `Content-Encoding: gzip, gzip` means that gzip was applied twice. It
requires two decoding stages, rather than one. Multiple `Content-Encoding`
field lines also form one ordered list and are subject to the same restriction.
See [RFC 9110, section 8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4).

When automatic decompression encounters multiple codings on a response with
content, the request returns `false`, sets `errCode` to
`SWOOLE_ERROR_HTTP_INVALID_PROTOCOL` and `statusCode` to
`SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET`, and closes the connection. Validation
happens before delivering body data to `body`, `write_func` or a download file.
The client does not return partially decoded content as a successful response.
HEAD responses and responses with no content by definition, such as 204 and
304, do not need decoding and are exempt from this check.

This restriction concerns nested coding layers. Multiple concatenated gzip
members under a single `Content-Encoding: gzip` remain supported.

## Receiving encoded data

Applications that need to process multiple codings themselves can disable
automatic decompression before making the request:

```php
$client->set(['body_decompression' => false]);
if ($client->get('/resource')) {
    $encodedBody = $client->body;
    $contentEncoding = $client->headers['content-encoding'] ?? null;
    // Interpret all declared codings and decode in reverse order if needed.
}
```

With this setting, `body`, `write_func` and `download()` receive the original
encoded representation. HTTP transfer framing, such as chunk boundaries, is
still removed. Response headers retain their declared values; repeated header
fields can be represented as an array of values.

`http_compression` controls the client's automatic `Accept-Encoding` request
header. It is separate from `body_decompression`; turning it off alone does not
disable decoding of an encoded response sent by the server.
