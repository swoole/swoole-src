--TEST--
swoole_websocket_server: websocket push 3
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
var_dump(
    swoole_websocket_server::unpack(
        swoole_websocket_server::pack('Hello swoole!', WEBSOCKET_OPCODE_TEXT, true)
    )
);
?>
--EXPECT--
object(Swoole\WebSocket\Frame)#1 (4) {
  ["fd"]=>
  int(0)
  ["data"]=>
  string(13) "Hello swoole!"
  ["opcode"]=>
  int(1)
  ["finish"]=>
  bool(true)
}