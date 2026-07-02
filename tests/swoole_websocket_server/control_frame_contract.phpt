--TEST--
swoole_websocket_server: control frame payload contract
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\WebSocket\CloseFrame;
use Swoole\WebSocket\Frame;

$pingPayload = str_repeat('A', 126);
var_dump(Frame::pack($pingPayload, WEBSOCKET_OPCODE_PING, SWOOLE_WEBSOCKET_FLAG_FIN));

$closeFrame = new CloseFrame;
$closeFrame->code = WEBSOCKET_CLOSE_NORMAL;
$closeFrame->reason = str_repeat('B', 124);
var_dump(Frame::pack($closeFrame));
?>
--EXPECTF--
Warning: Swoole\WebSocket\Frame::pack(): websocket control frame payload must not exceed 125 bytes in %s on line %d
string(0) ""

Warning: Swoole\WebSocket\Frame::pack(): the max length of close reason is 123 in %s on line %d
string(0) ""
