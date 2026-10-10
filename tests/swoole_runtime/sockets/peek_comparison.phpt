--TEST--
swoole_runtime/sockets: MSG_PEEK preserves data with native and PHP hooks
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($writer, $reader) {
    if (defined('MSG_DONTWAIT') && MSG_DONTWAIT !== 0) {
        foreach ([MSG_PEEK | MSG_DONTWAIT, MSG_PEEK | MSG_DONTWAIT | MSG_WAITALL] as $flags) {
            $buffer = 'sentinel';
            if (@socket_recv($reader, $buffer, 3, $flags) !== false || $buffer !== null
                || !in_array(socket_last_error($reader), [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)) {
                throw new RuntimeException('Nonblocking peek did not report EAGAIN');
            }
        }
    }
    socket_write($writer, 'abcdef');
    $flagsList = [MSG_PEEK, MSG_PEEK, MSG_PEEK | MSG_WAITALL];
    if (defined('MSG_DONTWAIT') && MSG_DONTWAIT !== 0) {
        $flagsList[] = MSG_PEEK | MSG_DONTWAIT;
    }
    foreach ($flagsList as $flags) {
        if (socket_recv($reader, $buffer, 3, $flags) !== 3 || $buffer !== 'abc') {
            throw new RuntimeException('Peek did not return the requested prefix');
        }
    }
    if (socket_recv($reader, $buffer, 6, MSG_WAITALL) !== 6 || $buffer !== 'abcdef') {
        throw new RuntimeException('Peek consumed data');
    }
});

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_SOCKETS);
Swoole\Coroutine\run(function () {
    $domain = PHP_OS_FAMILY === 'Windows' ? AF_INET : AF_UNIX;
    socket_create_pair($domain, SOCK_STREAM, 0, $pair);
    [$writer, $reader] = $pair;
    socket_set_option($reader, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 0, 'usec' => 20000]);
    try {
        if ($reader->peek(3, 0.01) !== false || $reader->errCode !== SOCKET_ETIMEDOUT) {
            throw new RuntimeException('Peek did not respect its explicit timeout');
        }
        if (socket_recv($reader, $buffer, 3, MSG_PEEK) !== false || $buffer !== null
            || socket_last_error($reader) !== SOCKET_ETIMEDOUT) {
            throw new RuntimeException('Blocking peek did not respect the receive timeout');
        }
        if (defined('MSG_DONTWAIT') && MSG_DONTWAIT !== 0) {
            // A previous timeout must not leak into a subsequent nonblocking operation.
            $ran = false;
            Swoole\Coroutine::create(function () use (&$ran) {
                Swoole\Coroutine::sleep(0.001);
                $ran = true;
            });
            if ($reader->peek(3, 0, MSG_DONTWAIT) !== false
                || !in_array($reader->errCode, [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)
                || socket_recv($reader, $buffer, 3, MSG_PEEK | MSG_DONTWAIT) !== false
                || !in_array(socket_last_error($reader), [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK], true)
                || $ran) {
                throw new RuntimeException('Nonblocking peek waited or retained a timeout error');
            }
        }
        socket_set_option($reader, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
        Swoole\Coroutine::create(function () use ($writer) {
            Swoole\Coroutine::sleep(0.01);
            socket_write($writer, 'xyz');
        });
        if ($reader->peek(3) !== 'xyz'
            || socket_recv($reader, $buffer, 3, MSG_PEEK) !== 3 || $buffer !== 'xyz'
            || socket_read($reader, 3) !== 'xyz') {
            throw new RuntimeException('Peek did not wait for data without consuming it');
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
