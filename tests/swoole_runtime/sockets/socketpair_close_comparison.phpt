--TEST--
swoole_runtime/sockets: closing a socket pair endpoint delivers EOF while references remain
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
foreach ([0, SWOOLE_HOOK_SOCKETS] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () {
        foreach ([0, 1] as $index) {
            $domain = PHP_OS_FAMILY === 'Windows' ? AF_INET : AF_UNIX;
            if (!socket_create_pair($domain, SOCK_STREAM, 0, $pair)) {
                throw new RuntimeException('Cannot create socket pair');
            }
            $closed = false;
            $retained = $pair[$index];
            $peer = $pair[1 - $index];
            try {
                socket_set_option($peer, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
                if (socket_write($retained, 'queued') !== 6) {
                    throw new RuntimeException('Cannot write to socket pair');
                }
                socket_close($retained);
                $closed = true;
                // Both $pair and $retained keep the closed endpoint alive.
                if (socket_read($peer, 6) !== 'queued' || socket_read($peer, 1) !== '') {
                    throw new RuntimeException('Close required destroying the object to deliver EOF');
                }
            } finally {
                if (!$closed) {
                    socket_close($retained);
                }
                socket_close($peer);
            }
        }
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
