--TEST--
swoole_websocket_server: websocket frame pack rejects negative opcode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;

Assert::same(@Frame::pack('hello', -1), '');
echo "DONE\n";
?>
--EXPECT--
DONE
