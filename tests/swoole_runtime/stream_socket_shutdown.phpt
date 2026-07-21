--TEST--
swoole_runtime: stream_socket_shutdown return values
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--INI--
error_reporting=E_ALL
display_errors=1
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server   = null;
$sender   = null;
$receiver = null;

Co\run(function () use (&$server, &$sender, &$receiver): void {
    try {
        $server = stream_socket_server('tcp://127.0.0.1:0');

        if ($server === false) {
            throw new RuntimeException('Failed to create the loopback server.');
        }

        $address = stream_socket_get_name($server, false);

        if (!is_string($address)) {
            throw new RuntimeException('Failed to resolve the loopback server address.');
        }

        $sender   = stream_socket_client("tcp://{$address}");
        $receiver = stream_socket_accept($server, 1);

        if ($sender === false || $receiver === false) {
            throw new RuntimeException('Failed to create the loopback connection.');
        }

        fwrite($sender, 'payload');

        var_dump(stream_socket_shutdown($sender, STREAM_SHUT_WR));
        var_dump(stream_get_contents($receiver));
        var_dump(feof($receiver));
        var_dump(stream_socket_shutdown($sender, STREAM_SHUT_WR));
    } finally {
        foreach ([$sender, $receiver, $server] as $stream) {
            if (is_resource($stream)) {
                fclose($stream);
            }
        }
    }
});
?>
--EXPECT--
bool(true)
string(7) "payload"
bool(true)
bool(false)
