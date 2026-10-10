--TEST--
swoole_runtime/sockets: warn about UNIX datagram recvfrom lengths exceeding 64 KiB
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
skip('Large UNIX datagrams require Linux', PHP_OS_FAMILY !== 'Linux');
?>
--FILE--
<?php
foreach ([0, SWOOLE_HOOK_SOCKETS] as $flags) {
    Swoole\Runtime::enableCoroutine($flags);
    Swoole\Coroutine\run(function () use ($flags) {
        $base = sys_get_temp_dir() . '/sw-dgram-warning-' . getmypid() . '-' . $flags;
        $sender = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        $receiver = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        $udp = socket_create(AF_INET, SOCK_DGRAM, 0);
        $warnings = [];
        set_error_handler(function ($severity, $message) use (&$warnings) {
            $warnings[] = $message;
            return true;
        }, E_USER_WARNING);
        try {
            if (!socket_bind($sender, $base . '-sender') || !socket_bind($receiver, $base . '-receiver')) {
                throw new RuntimeException('Cannot bind UNIX datagram sockets');
            }
            socket_set_option($sender, SOL_SOCKET, SO_SNDBUF, 262144);
            socket_set_option($receiver, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
            foreach ([65536, 65537] as $length) {
                $payload = str_repeat('x', $length);
                $expectedLength = $flags ? min($length, 65536) : $length;
                if (socket_sendto($sender, $payload, $length, 0, $base . '-receiver') !== $length
                    || socket_recvfrom($receiver, $buffer, $length, 0, $address) !== $expectedLength
                    || $buffer !== substr($payload, 0, $expectedLength) || $address !== $base . '-sender') {
                    throw new RuntimeException('The warning changed UNIX datagram receive behavior');
                }
                if (count($warnings) !== ($flags && $length > 65536 ? 1 : 0)) {
                    throw new RuntimeException('The size warning did not respect the 64 KiB boundary');
                }
            }
            if ($flags) {
                foreach (['sockets extension', '64 KiB', 'truncated', 'discarded'] as $text) {
                    if (!str_contains($warnings[0], $text)) {
                        throw new RuntimeException("Missing datagram compatibility explanation: $text");
                    }
                }
            }
            // An oversized receive buffer is supported for ordinary UDP and must not warn.
            socket_bind($udp, '127.0.0.1', 0);
            socket_getsockname($udp, $ip, $port);
            socket_set_option($udp, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
            if (socket_sendto($udp, 'udp', 3, 0, $ip, $port) !== 3
                || socket_recvfrom($udp, $buffer, 65537, 0, $address, $peerPort) !== 3 || $buffer !== 'udp'
                || count($warnings) !== ($flags ? 1 : 0)) {
                throw new RuntimeException('A non-UNIX receive triggered a size warning');
            }
        } finally {
            restore_error_handler();
            foreach ([$sender, $receiver, $udp] as $socket) {
                socket_close($socket);
            }
            foreach (['-sender', '-receiver'] as $suffix) {
                if (file_exists($base . $suffix)) {
                    unlink($base . $suffix);
                }
            }
        }
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
