--TEST--
swoole_websocket_server: unpack returns false for an incomplete frame
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

printf("Frame::unpack returns: %s\n", (string) (new ReflectionMethod(Frame::class, 'unpack'))->getReturnType());
printf("Server::unpack returns: %s\n", (string) (new ReflectionMethod(Server::class, 'unpack'))->getReturnType());

Assert::false(Frame::unpack("\x81"));
Assert::same(swoole_last_error(), SWOOLE_ERROR_PROTOCOL_ERROR);
Assert::false(Server::unpack("\x81"));
echo "DONE\n";
?>
--EXPECT--
Frame::unpack returns: Swoole\WebSocket\Frame|false
Server::unpack returns: Swoole\WebSocket\Frame|false
DONE
