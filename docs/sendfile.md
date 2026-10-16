# File sending options

`Swoole\Http\Response::sendfile()` and `Swoole\Server::sendfile()` accept either
a filename string or a `Swoole\SendFile` descriptor. Existing string calls retain
their offset and length parameters:

```php
$response->sendfile($path, 1024, 4096);
$server->sendfile($fd, $path, 1024, 4096);
```

Use a descriptor to configure a transfer without adding positional arguments:

```php
$file = new Swoole\SendFile($path);
$file->offset = 1024;
$file->length = 4096;
$file->deleteAfterSend = true;

$response->sendfile($file);
// Or: $server->sendfile($fd, $file);
```

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `filename` | readonly string | Constructor argument | Local source pathname. |
| `offset` | int | `0` | Byte offset; must be nonnegative. |
| `length` | int | `0` | Bytes to send; zero sends the remaining file. |
| `deleteAfterSend` | bool | `false` | Transfer responsibility for deleting the file to Swoole. |

For descriptor calls, set ranges on the object; supplying separate offset or
length arguments raises `ValueError`. Options are captured for each call.
Creating or destroying a descriptor does not open, close, or remove its file.
Descriptors cannot be cloned or serialized.

## Automatic cleanup

With `deleteAfterSend`, use a temporary file exclusively owned by one transfer.
Do not submit the same pathname through another descriptor, delete it, or replace
it while the transfer is pending. Once Swoole takes responsibility for cleanup,
the descriptor cannot be submitted again, even if its properties are changed.

Validation errors before ownership transfer preserve the file and allow retry.
After ownership transfer, Swoole removes the file when the native transfer ends,
including a send failure, discarded queued send, or client disconnect. This is a
local transfer boundary, not confirmation that the peer application consumed the
data. A `false` return after ownership transfer can therefore accompany deletion.
Abrupt process termination cannot guarantee file cleanup.

These interfaces are introduced on `master`; they are not available on the
`6.1` and `6.2` maintenance branches.
