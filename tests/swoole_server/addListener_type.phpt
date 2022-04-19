--TEST--
swoole_server: addlistener type
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server(TCP_SERVER_HOST, get_one_free_port());
$port = $server->addListener(TCP_SERVER_HOST, get_one_free_port(), SWOOLE_SOCK_TCP | SWOOLE_SSL);

Assert::assert((SWOOLE_SOCK_TCP | SWOOLE_SSL) === $port->type);
?>
--EXPECT--
