--TEST--
swoole_runtime/sockets: empty UDP datagrams match native recvfrom
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
        $receiver = socket_create(AF_INET, SOCK_DGRAM, 0);
        $senders = [socket_create(AF_INET, SOCK_DGRAM, 0), socket_create(AF_INET, SOCK_DGRAM, 0)];
        try {
            socket_bind($receiver, '127.0.0.1', 0);
            socket_getsockname($receiver, $destination, $destinationPort);
            socket_set_option($receiver, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
            foreach ($senders as $sender) {
                socket_bind($sender, '127.0.0.1', 0);
            }
            foreach ([[0, ''], [0, 'hello'], [1, ''], [0, ''], [1, 'tail']] as [$index, $payload]) {
                $sender = $senders[$index];
                socket_getsockname($sender, $expectedAddress, $expectedPort);
                $buffer = $address = $port = 'sentinel';
                if (socket_sendto($sender, $payload, strlen($payload), 0, $destination, $destinationPort) !== strlen($payload)
                    || socket_recvfrom($receiver, $buffer, 16, 0, $address, $port) !== strlen($payload)
                    || $buffer !== $payload || $address !== $expectedAddress || $port !== $expectedPort) {
                    throw new RuntimeException('recvfrom differs from native empty datagram semantics');
                }
            }
        } finally {
            socket_close($receiver);
            foreach ($senders as $sender) {
                socket_close($sender);
            }
        }
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
