--TEST--
swoole_runtime/sockets: socket_recv sets its output to null for empty datagrams like native sockets
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
        $socket = socket_create(AF_INET, SOCK_DGRAM, 0);
        try {
            socket_bind($socket, '127.0.0.1', 0);
            socket_getsockname($socket, $address, $port);
            socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
            foreach ([0, MSG_WAITALL] as $receiveFlags) {
                if (socket_sendto($socket, '', 0, 0, $address, $port) !== 0
                    || socket_sendto($socket, '0', 1, 0, $address, $port) !== 1) {
                    throw new RuntimeException('Cannot queue the test datagrams');
                }
                foreach ([MSG_PEEK, MSG_PEEK | MSG_WAITALL, $receiveFlags] as $peekOrReceiveFlags) {
                    $buffer = 'sentinel';
                    if (socket_recv($socket, $buffer, 16, $peekOrReceiveFlags) !== 0 || $buffer !== null) {
                        throw new RuntimeException('An empty datagram did not clear the output to null');
                    }
                }
                if (socket_recv($socket, $buffer, 1, 0) !== 1 || $buffer !== '0') {
                    throw new RuntimeException('Peek consumed an empty datagram or a subsequent packet was lost');
                }
            }
        } finally {
            socket_close($socket);
        }
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
