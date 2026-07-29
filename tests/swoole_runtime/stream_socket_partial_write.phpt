--TEST--
swoole_runtime: nonblocking stream writes preserve partial byte counts
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

        $senderSocket   = socket_import_stream($sender);
        $receiverSocket = socket_import_stream($receiver);

        if ($senderSocket === false || $receiverSocket === false) {
            throw new RuntimeException('Failed to import the loopback sockets.');
        }

        if (!socket_set_option($senderSocket, SOL_SOCKET, SO_SNDBUF, 4096)
            || !socket_set_option($receiverSocket, SOL_SOCKET, SO_RCVBUF, 4096)) {
            throw new RuntimeException('Failed to reduce the loopback socket buffers.');
        }

        stream_set_blocking($sender, false);

        $payload                     = str_repeat('partial-write:', 65536);
        $firstWrite                  = fwrite($sender, $payload);
        $secondWrite                 = fwrite($sender, $payload);
        $senderOpenAfterBackpressure = !feof($sender);

        stream_socket_shutdown($sender, STREAM_SHUT_WR);
        stream_set_blocking($receiver, true);

        $received = stream_get_contents($receiver);

        var_dump(is_int($firstWrite) && $firstWrite > 0 && $firstWrite < strlen($payload));
        var_dump($secondWrite === 0);
        var_dump($senderOpenAfterBackpressure);
        var_dump(is_string($received) && strlen($received) === $firstWrite);
        var_dump(is_string($received) && $received === substr($payload, 0, $firstWrite));
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
bool(true)
bool(true)
bool(true)
bool(true)
