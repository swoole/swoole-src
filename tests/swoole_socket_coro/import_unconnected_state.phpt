--TEST--
swoole_socket_coro: importing listeners and unconnected datagrams preserves their state
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
Swoole\Coroutine\run(function () {
    foreach (['tcp', 'udp'] as $scheme) {
        $flags = STREAM_SERVER_BIND | ($scheme === 'tcp' ? STREAM_SERVER_LISTEN : 0);
        $stream = stream_socket_server("$scheme://127.0.0.1:0", $errno, $errstr, $flags);
        if ($stream === false) {
            throw new RuntimeException("Cannot create $scheme stream: $errstr");
        }
        $socket = null;
        try {
            $socket = Swoole\Coroutine\Socket::import($stream);
            if ($socket === false || $socket->errCode !== 0 || $socket->errMsg !== '') {
                throw new RuntimeException('Import reported an error for an unconnected socket');
            }
            if ($socket->shutdown() !== false || $socket->errCode !== SOCKET_ENOTCONN) {
                throw new RuntimeException('An unconnected socket was treated as connected');
            }
        } finally {
            if ($socket instanceof Swoole\Coroutine\Socket) {
                $socket->close();
            }
            if (is_resource($stream)) {
                fclose($stream);
            }
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
