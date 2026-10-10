--TEST--
swoole_runtime/sockets: socket pairs support half-close like native sockets
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($first, $second) {
    if (socket_write($first, 'request') !== 7 || !socket_shutdown($first, STREAM_SHUT_WR)
        || socket_read($second, 7) !== 'request' || socket_read($second, 1) !== '') {
        throw new RuntimeException('Half-close did not deliver pending data followed by EOF');
    }
    if (socket_write($second, 'reply') !== 5 || socket_read($first, 5) !== 'reply') {
        throw new RuntimeException('Half-close interrupted reverse communication');
    }
    if (!socket_shutdown($second, STREAM_SHUT_WR) || socket_read($first, 1) !== '') {
        throw new RuntimeException('The second socket was not initialized as connected');
    }
});

// Connected datagram pairs also support shutdown, without a connect() call.
if (PHP_OS_FAMILY !== 'Windows') {
    Swoole\Coroutine\run(function () {
        $pair = swoole_coroutine_socketpair(AF_UNIX, SOCK_DGRAM, 0);
        try {
            foreach ($pair as $socket) {
                if (!$socket->shutdown(STREAM_SHUT_WR)) {
                    throw new RuntimeException('Datagram pair was not initialized as connected');
                }
            }
        } finally {
            foreach ($pair as $socket) {
                $socket->close();
            }
        }
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
