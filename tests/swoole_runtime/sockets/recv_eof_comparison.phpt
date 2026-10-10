--TEST--
swoole_runtime/sockets: socket_recv sets its output to null at EOF like native sockets
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/socket_hook_comparison.inc';

run_socket_hook_comparison(function ($writer, $reader) {
    socket_write($writer, '0');
    if (socket_recv($reader, $buffer, 1, MSG_PEEK) !== 1 || $buffer !== '0'
        || socket_recv($reader, $buffer, 1, 0) !== 1 || $buffer !== '0') {
        throw new RuntimeException('A nonempty zero string was treated as EOF');
    }
    if (!socket_shutdown($writer, STREAM_SHUT_WR)) {
        throw new RuntimeException('Cannot half-close the writer');
    }
    $flagsList = [0, MSG_PEEK, MSG_WAITALL, MSG_PEEK | MSG_WAITALL];
    if (defined('MSG_DONTWAIT') && MSG_DONTWAIT !== 0) {
        $flagsList[] = MSG_DONTWAIT;
        $flagsList[] = MSG_PEEK | MSG_DONTWAIT;
    }
    foreach ($flagsList as $flags) {
        $buffer = 'sentinel';
        $alias = &$buffer;
        if (socket_recv($reader, $buffer, 16, $flags) !== 0 || $buffer !== null || $alias !== null) {
            throw new RuntimeException('EOF did not return zero and clear the output to null');
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
