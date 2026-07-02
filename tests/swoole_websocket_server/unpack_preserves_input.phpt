--TEST--
swoole_websocket_server: unpack preserves input buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\WebSocket\Frame;

$payload = "masked-payload";
$flags = SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_MASK;
$packed = Frame::pack($payload, WEBSOCKET_OPCODE_TEXT, $flags);
$original = $packed;

$frame = Frame::unpack($packed);

var_dump((ord($packed[1]) & 0x80) === 0x80);
var_dump($packed === $original);
var_dump(bin2hex($packed) === bin2hex($original));
var_dump($frame->data === $payload);
var_dump($frame->opcode === WEBSOCKET_OPCODE_TEXT);
var_dump($frame->finish === true);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
