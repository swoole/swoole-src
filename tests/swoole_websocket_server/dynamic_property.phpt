--TEST--
swoole_websocket_server: Creation of dynamic property is deprecated.
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initFreePorts(10);
$websocket = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort());
$port1 = $websocket->listen("127.0.0.1", $pm->getFreePort(), SWOOLE_SOCK_TCP);
$port2 = $websocket->listen("127.0.0.1", $pm->getFreePort(), SWOOLE_SOCK_TCP);
$port3 = $websocket->listen("127.0.0.1", $pm->getFreePort(), SWOOLE_SOCK_TCP);
$port1->on('handshake', function($request, $response) {});
var_dump($port1->getCallback('handshake') != null);

$port2->on('HANDSHAKE', function($request, $response) {});
var_dump($port1->getCallback('HANDSHAKE') != null);

$port3->on('handShake', function($request, $response) {});
var_dump($port1->getCallback('handShake') != null);
echo 'DONE';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
DONE
