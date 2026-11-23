# Coroutine HTTP client request bodies

`Swoole\Coroutine\Http\Client::setData()`, `addFile()` and `addData()` configure
different parts of a request. `setData()` replaces the configured request body;
`addFile()` and `addData()` append upload parts. They can be combined when
`setData()` receives an array.

This document describes the current implementation on `master`. PHP stream
resources and an optional stream length for `setData()` are being discussed in
[#6442](https://github.com/swoole/swoole-src/issues/6442); they are not part of
the API documented here.

## Choosing the request body format

The presence of upload parts selects multipart encoding when the request is
sent.

| Configured data | Request body |
| --- | --- |
| `setData(string)`, with no upload parts | The string is sent as the raw body. |
| `setData(array)`, with no upload parts | The array is encoded as `application/x-www-form-urlencoded`. |
| `addFile()` and/or `addData()`, with no `setData()` body | A `multipart/form-data` body containing the upload parts. |
| `setData(array)` with `addFile()` and/or `addData()` | One `multipart/form-data` body containing ordinary fields and upload parts. |
| `setData(string)` with `addFile()` and/or `addData()` | Multipart encoding is selected and the raw string is ignored. |

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

Disk file parts use the socket's `sendfile()` path. In-memory parts use the
supplied PHP string and a write buffer. For a large local file uploaded as
multipart, `addFile()` avoids first loading the entire file into a PHP string;
`addData()` does not provide that memory saving.
