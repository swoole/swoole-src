--TEST--
swoole_runtime/sockets: normal reads preserve following bytes for binary reads and recv
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($writer, $reader) {
    socket_write($writer, "first\nSECOND\r\nTAIL");
    if (socket_read($reader, 64, PHP_NORMAL_READ) !== "first\n"
        || socket_read($reader, 3, PHP_BINARY_READ) !== 'SEC'
        || socket_recv($reader, $buffer, 3, MSG_PEEK) !== 3 || $buffer !== 'OND'
        || socket_recv($reader, $buffer, 3, MSG_WAITALL) !== 3 || $buffer !== 'OND'
        || socket_read($reader, 64, PHP_NORMAL_READ) !== "\r"
        || socket_read($reader, 64, PHP_NORMAL_READ) !== "\n"
        || socket_read($reader, 64, PHP_BINARY_READ) !== 'TAIL') {
        throw new RuntimeException('Switching read modes lost data');
    }
    socket_write($writer, "abcdef\n");
    if (socket_read($reader, 3, PHP_NORMAL_READ) !== 'abc'
        || socket_read($reader, 64, PHP_BINARY_READ) !== "def\n") {
        throw new RuntimeException('Length-limited normal read consumed following bytes');
    }
});

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_SOCKETS);
Swoole\Coroutine\run(function () {
    $domain = PHP_OS_FAMILY === 'Windows' ? AF_INET : AF_UNIX;
    socket_create_pair($domain, SOCK_STREAM, 0, $pair);
    [$writer, $reader] = $pair;
    socket_set_option($reader, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
    try {
        Swoole\Coroutine::create(function () use ($writer) {
            socket_write($writer, 'frag');
            Swoole\Coroutine::sleep(0.01);
            socket_write($writer, "mented\nBODY");
        });
        if (socket_read($reader, 64, PHP_NORMAL_READ) !== "fragmented\n"
            || socket_read($reader, 64) !== 'BODY') {
            throw new RuntimeException('Fragmented normal read consumed the body');
        }
    } finally {
        socket_close($writer);
        socket_close($reader);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
