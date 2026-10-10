--TEST--
swoole_runtime/sockets: length validation matches native sockets without unexpected IO
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($writer, $reader) {
    foreach (['socket_write', 'socket_send'] as $function) {
        $args = $function === 'socket_write' ? [] : [0];
        if ($function($writer, 'abc', 0, ...$args) !== 0) {
            throw new RuntimeException('Zero length sent data');
        }
        try {
            $function($writer, 'abc', -1, ...$args);
            throw new RuntimeException('Negative length was accepted');
        } catch (ValueError $e) {
        }
        socket_write($writer, 'X');
        if (socket_read($reader, 64) !== 'X') {
            throw new RuntimeException('Invalid or zero length consumed the output buffer');
        }
        foreach ([2, 100] as $length) {
            $expected = substr('abc', 0, $length);
            if ($function($writer, 'abc', $length, ...$args) !== strlen($expected)
                || socket_read($reader, 64) !== $expected) {
                throw new RuntimeException('Incorrect bounded send');
            }
        }
    }
    if (socket_write($writer, 'abc', null) !== 3 || socket_read($reader, 64) !== 'abc') {
        throw new RuntimeException('Nullable write length failed');
    }
    foreach ([0, -1, PHP_INT_MAX] as $length) {
        socket_write($writer, 'abc');
        $buffer = 'sentinel';
        if (socket_read($reader, $length) !== false || socket_read($reader, $length, PHP_NORMAL_READ) !== false
            || socket_recv($reader, $buffer, $length, 0) !== false || $buffer !== 'sentinel'
            || socket_recv($reader, $buffer, $length, MSG_PEEK) !== false || $buffer !== 'sentinel'
            || socket_read($reader, 3) !== 'abc') {
            throw new RuntimeException('Invalid receive length consumed data or changed its output');
        }
    }
    socket_write($writer, "a\nb");
    if (socket_read($reader, 3, 999) !== "a\nb") {
        throw new RuntimeException('Only PHP_NORMAL_READ may select line reading');
    }

    $udp = socket_create(AF_INET, SOCK_DGRAM, 0);
    try {
        socket_bind($udp, '127.0.0.1', 0);
        socket_getsockname($udp, $ip, $port);
        socket_set_option($udp, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
        if (socket_sendto($udp, 'abc', 0, 0, $ip, $port) !== 0
            || socket_recv($udp, $buffer, 16, 0) !== 0) {
            throw new RuntimeException('Zero-length sendto sent a nonempty datagram');
        }
        try {
            socket_sendto($udp, 'abc', -1, 0, $ip, $port);
            throw new RuntimeException('Negative sendto length was accepted');
        } catch (ValueError $e) {
        }
        socket_sendto($udp, 'abc', 2, 0, $ip, $port);
        foreach ([0, -1, PHP_INT_MAX] as $length) {
            $buffer = $address = $peerPort = 'sentinel';
            if (socket_recvfrom($udp, $buffer, $length, 0, $address, $peerPort) !== false
                || $buffer !== 'sentinel' || $address !== 'sentinel' || $peerPort !== 'sentinel') {
                throw new RuntimeException('Invalid recvfrom length changed its output');
            }
        }
        if (socket_recvfrom($udp, $buffer, 16, 0, $address, $peerPort) !== 2 || $buffer !== 'ab') {
            throw new RuntimeException('Invalid recvfrom length consumed the datagram');
        }
    } finally {
        socket_close($udp);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
