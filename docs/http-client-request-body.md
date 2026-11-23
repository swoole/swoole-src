# Coroutine HTTP client request bodies

`Swoole\Coroutine\Http\Client::setData()`, `addFile()` and `addData()` configure
different parts of a request. `setData()` replaces the configured request body;
`addFile()` and `addData()` append upload parts. They can be combined when
`setData()` receives an array.

This document describes the development implementation on `master`, including
the PHP stream upload support discussed in
[#6442](https://github.com/swoole/swoole-src/issues/6442).

## Choosing the request body format

The presence of upload parts selects multipart encoding when the request is
sent.

| Configured data | Request body |
| --- | --- |
| `setData(string)`, with no upload parts | The string is sent as the raw body. |
| `setData(array)`, with no upload parts | The array is encoded as `application/x-www-form-urlencoded`. |
| `setData(resource)`, with no upload parts | Bytes from a readable PHP stream are sent as the raw body. |
| `addFile()` and/or `addData()`, with no `setData()` body | A `multipart/form-data` body containing the upload parts. |
| `setData(array)` with `addFile()` and/or `addData()` | One `multipart/form-data` body containing ordinary fields and upload parts. |
| `setData(string)` with `addFile()` and/or `addData()` | Multipart encoding is selected and the raw string is ignored. |
| `setData(resource)` with `addFile()` and/or `addData()` | Rejected with `ValueError`, in either configuration order. |

Set the method explicitly, for example with `setMethod('POST')`, when using
`execute()` to send an upload.

## Combining form fields and files

Inside a coroutine:

```php
$client = new Swoole\Coroutine\Http\Client('127.0.0.1', 9501);
$client->setMethod('POST');
$client->setData(['name' => 'example']);
$client->addFile('/tmp/photo.jpg', 'photo');
$client->execute('/upload');
```

This sends one request with a text field named `name` and a file part named
`photo`. With normal request parsing enabled, a Swoole HTTP server exposes them
separately:

```php
$request->post['name'];                  // 'example'
$request->files['photo']['name'];        // 'photo.jpg'
$request->files['photo']['tmp_name'];    // Temporary uploaded file path
```

The configuration is stored separately. `setData()` writes `requestBody`, while
`addFile()` appends an entry to `uploadFiles`. Calling `setData(array)` before or
after `addFile()` produces the same combination for the pending request.

## Combining form fields and in-memory file content

`addData()` adds an upload part whose content is already held in a PHP string:

```php
$client->setData(['name' => 'example']);
$client->addData($content, 'photo', 'image/jpeg', 'photo.jpg');
$client->execute('/upload');
```

The server receives the same field and file structure as in the `addFile()`
example. The data source differs: `addFile()` reads a local file, while
`addData()` uses the supplied string. `addData()` creates a file part with a
filename and content type; use `setData(array)` for ordinary text fields.

For `addData()`, an omitted content type defaults to
`application/octet-stream`, and an omitted filename defaults to the part name.
For `addFile()`, the default filename is the basename of the supplied path and
the default content type is inferred from that path.

Both kinds of upload part can be included in the same request:

```php
$client->setData(['name' => 'example', 'category' => 'photos']);
$client->addFile('/tmp/photo.jpg', 'photo');
$client->addData('Description text', 'description', 'text/plain', 'description.txt');
$client->execute('/upload');
```

## Replacement and append rules

Each `setData()` call replaces the entire previous `requestBody` value. Array
arguments from separate calls are not merged:

```php
$client->setData(['first' => 'one']);
$client->setData(['second' => 'two']);
$client->addFile('/tmp/photo.jpg', 'photo');
$client->execute('/upload');
```

Only the `second` field and the `photo` file part are sent.

Each successful `addFile()` or `addData()` call appends to the same upload-part
list. Neither method replaces earlier parts or clears `requestBody`. Parts are
sent in the order they were added, including when the two methods are mixed.
Repeated part names are appended too; how those names are represented after
parsing depends on the receiving server.

For multipart ordinary fields, the current implementation emits non-null array
entries with string keys and converts their values to strings. Integer-keyed
entries and entries with `null` values are skipped. Use a flat array of scalar
field values.

Calling `post($path, $data)` sets `requestBody` to its `$data` argument before
sending. That argument therefore replaces any earlier `setData()` value, while
pending upload parts still select multipart encoding.

## Raw strings with pending upload parts

This configuration does not send the JSON string:

```php
$client->setData('{"name":"example"}');
$client->addData('File content', 'attachment', 'text/plain', 'attachment.txt');
$client->execute('/upload');
```

The current implementation sends only the multipart upload part. It does not
report a conflict, turn the raw string into a form field, or let the string
replace the upload parts. This also applies when `setData(string)` is called
after the upload parts have been added.

To include JSON as an ordinary multipart field, give it a field name:

```php
$client->setData(['metadata' => '{"name":"example"}']);
$client->addFile('/tmp/photo.jpg', 'photo');
```

To send a raw body instead, ensure no upload parts remain configured. For a
pending request that already has upload parts, clear the list explicitly:

```php
$client->uploadFiles = [];
$client->setHeaders(['Content-Type' => 'application/json']);
$client->setData('{"name":"example"}');
$client->execute('/upload');
```

`setData()` alone does not clear `uploadFiles`.

## Raw string memory use

For a raw string body, the client retains the original PHP string while sending
and writes the headers and body without concatenating them into another full
request buffer. This applies to both HTTP and HTTPS. A blocked write keeps the
original string alive even if `requestBody` is replaced in another coroutine.

`setData(file_get_contents($path))` still loads the whole file into a PHP string.
Avoiding the second full-size copy reduces upload memory, but does not turn that
call into a streaming upload.

## Sending a PHP stream as the raw body

The signature follows PHP's stub convention for resource arguments:

```php
class Client
{
    /** @param array|string|resource $data */
    public function setData($data, ?int $length = null): bool {}
}
```

PHP does not support a native `resource` type declaration. The PHPDoc union
describes the three accepted types; the implementation validates them and
rejects other types with `TypeError`. A resource must be an open, readable PHP
stream. A directory or write-only stream is rejected with `ValueError`.

For example, inside a coroutine:

```php
$stream = fopen('/tmp/archive.bin', 'rb');
try {
    fseek($stream, 1024);
    $client->setMethod('PUT');
    $client->setHeaders(['Content-Type' => 'application/octet-stream']);
    $client->setData($stream, 4 * 1024 * 1024);
    $client->execute('/archive');
} finally {
    fclose($stream);
}
```

This sends exactly 4 MiB starting at the stream's current position. There is no
separate offset parameter. The starting position and byte count are captured
when execution starts, so `fseek()` after `setData()` and before `execute()`
takes effect.

| `$length` | Behavior |
| --- | --- |
| `null` or omitted | Infer the remaining size of an unfiltered, seekable stream whose `fstat()` reports a regular file size. This includes normal files, `php://memory` and `php://temp`. |
| `0` | Send an empty body without reading the source. |
| Positive integer | Send exactly this many bytes; leave the remaining bytes for later use. |
| Negative integer | Throw `ValueError`. |

A non-null length is only valid for a resource. If the remaining length cannot
be inferred, an explicit length is required; validation fails before headers
are sent. This applies to pipes and streams with read filters. The explicit
length counts the bytes returned by the stream, including any filter's output.
If a known remaining size is smaller than the explicit length, the request is
rejected before sending.

The client generates `Content-Length` and reads at most 64 KiB at a time,
sending each block before reading the next. It does not load the entire stream
or concatenate its contents into a request buffer. Both HTTP and HTTPS use
this path. Transfer-Encoding, including chunked uploads, is not supported for
this client; a configured `Transfer-Encoding` header is rejected for every
request body mode, including strings, arrays and multipart uploads.

Reads use the PHP stream API directly. A normal stream can block, while a
coroutine file stream can yield. The caller chooses the stream and hook
configuration. The client retains the active stream during the request, even
if another coroutine replaces `requestBody`, and does not close or implicitly
rewind the caller's stream after sending.

For automatic 502/503 response retries, an unfiltered, seekable stream is
restored to its original starting position and sent again with the original
byte count. Pending `setData()` changes do not replace that retry source. A
non-seekable or filtered stream is sent once, and the received 502/503 response
is returned without an automatic replay. A failed rewind fails the request.
As with other body modes, defer mode does not automatically retry responses.

An early EOF, a read that makes no progress, a read exception or a failed send
abandons the connection, so a partial request cannot contaminate a later
exchange. PHP exceptions from stream operations propagate to the caller.

Stream bodies cannot be combined with `addFile()` or `addData()`. Checks apply
in either configuration order and again when sending, including when public
properties were changed directly. The existing array-plus-multipart and
string-plus-multipart rules above are unchanged. `post($path, $stream)` also
supports a raw stream body, with its remaining length inferred; use `setData()`
and `execute()` when an explicit length is needed.

## PHP cURL hook file uploads

The PHP cURL hook uses the stream upload path for seekable standard file,
memory and temporary streams with a configured `CURLOPT_INFILESIZE` that fits
the remaining source. It sends from the current position in bounded blocks,
retains the configured length across address failover and restores the original
position when a redirect requires the body to be sent again. It does not close
the caller's stream. Unknown-length and non-seekable inputs retain the hook's
buffered upload path.

## Compressed request bodies

HTTP request bodies can use a content coding such as gzip. The sender supplies
the encoded bytes and declares the coding with `Content-Encoding`. The
receiving endpoint must support that coding and decode the body; it may reject
an unsupported coding with `415 Unsupported Media Type`. See
[RFC 9110, section 8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4).

The client's `http_compression` option advertises acceptable response codings
through `Accept-Encoding`; it does not compress request bodies. The
`body_decompression` option controls response decoding. To send compressed
JSON, for example:

```php
$client->setHeaders([
    'Content-Type' => 'application/json',
    'Content-Encoding' => 'gzip',
]);
$client->post('/upload', gzencode($json));
```

The client calculates `Content-Length` from the compressed string's byte count.
Setting `Content-Encoding` alone does not transform the supplied data.

A file that already contains a gzip-encoded body can also be sent without
loading the whole file into a string:

```php
$stream = fopen('/tmp/payload.json.gz', 'rb');
try {
    $client->setMethod('POST');
    $client->setHeaders([
        'Content-Type' => 'application/json',
        'Content-Encoding' => 'gzip',
    ]);
    $client->setData($stream);
    $client->execute('/upload');
} finally {
    fclose($stream);
}
```

Compressing while reading usually leaves the final compressed length unknown
until the compressor finishes. The stream upload path currently requires a
known output length, so it does not support this unknown-length case. Supplying
the uncompressed length would produce incorrect framing. Supporting it in this
HTTP/1.1 client would require chunked request uploads (or buffering/spooling
the compressed output first to determine its size). `Content-Encoding: gzip`
and `Transfer-Encoding: chunked` serve different purposes and can be combined:
one describes the encoded content, the other frames its transfer.

## Multipart assembly and memory use

When upload parts are present, the client generates a boundary and calculates
one `Content-Length` for the complete multipart body. That length includes the
ordinary fields, part headers, file content, separators and closing boundary.
Let the client generate the multipart content type and boundary rather than
setting a conflicting `Content-Type` header.

It sends the HTTP headers and ordinary fields first, then each upload part in
registration order, and finally the closing boundary. Field and file data are
combined into one HTTP request during sending; the whole multipart body does
not have to be concatenated into one PHP string.

Disk file parts use the socket's `sendfile()` path. `addData()` retains the
supplied PHP string and sends the part header, content and separator with
vectored writes, without copying the complete content into another buffer.
The original string stays alive during blocked writes and uses PHP's normal
copy-on-write behavior if the caller changes its variable.

For a large local file uploaded as multipart, `addFile()` avoids first loading
the entire file into a PHP string. `addData()` still requires the content to
exist as a string, even though it no longer creates additional full-size copies.
