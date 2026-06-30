--TEST--
swoole_websocket_server: websocket close frame code is parsed as unsigned
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;

$frame = Frame::unpack("\x88\x02\x80\x00");
Assert::same($frame->code, 32768);
echo "DONE\n";
?>
--EXPECT--
DONE
