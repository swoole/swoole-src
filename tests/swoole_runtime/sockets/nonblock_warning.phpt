--TEST--
swoole_runtime/sockets: nonblocking compatibility warning describes the timeout simulation
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($writer, $reader) {
    $hooked = $reader instanceof Swoole\Coroutine\Socket;
    $warnings = [];
    set_error_handler(function ($severity, $message) use (&$warnings) {
        $warnings[] = $message;
        return true;
    }, E_USER_WARNING);
    try {
        for ($transition = 1; $transition <= 2; $transition++) {
            if (!socket_set_nonblock($reader) || !socket_set_nonblock($reader)
                || count($warnings) !== ($hooked ? $transition : 0)) {
                throw new RuntimeException('Wrong warning count when enabling nonblocking mode');
            }
            if ($hooked) {
                foreach (['sockets extension', '1 ms', 'SO_RCVTIMEO', 'suspend', 'ETIMEDOUT', 'EAGAIN', 'still wait'] as $text) {
                    if (!str_contains($warnings[$transition - 1], $text)) {
                        throw new RuntimeException("Missing compatibility explanation: $text");
                    }
                }
                if (socket_get_option($reader, SOL_SOCKET, SO_RCVTIMEO) !== ['sec' => 0, 'usec' => 1000]) {
                    throw new RuntimeException('The existing 1 ms simulation changed');
                }
            }
            $buffer = 'sentinel';
            if (socket_recv($reader, $buffer, 1, 0) !== false || $buffer !== null) {
                throw new RuntimeException('Empty receive unexpectedly succeeded');
            }
            $errors = $hooked ? [SOCKET_ETIMEDOUT] : [SOCKET_EAGAIN, SOCKET_EWOULDBLOCK];
            if (!in_array(socket_last_error($reader), $errors, true)) {
                throw new RuntimeException('The warning changed existing error behavior');
            }
            if (!socket_set_block($reader)
                || socket_get_option($reader, SOL_SOCKET, SO_RCVTIMEO) !== ['sec' => 1, 'usec' => 0]) {
                throw new RuntimeException('Blocking mode did not restore the original timeout');
            }
        }
    } finally {
        restore_error_handler();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
