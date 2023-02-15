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
$port1->on('beforehandshakeresponse', function($request, $response) {});
var_dump($port1->getCallback('handshake') != null);
var_dump($port1->getCallback('BeforeHandshakeResponse') != null);

$port2->on('HANDSHAKE', function($request, $response) {});
$port2->on('BEFOREHANDSHAKERESPONSE', function($request, $response) {});
var_dump($port1->getCallback('HANDSHAKE') != null);
var_dump($port1->getCallback('BEFOREHANDSHAKERESPONSE') != null);

$port3->on('handShake', function($request, $response) {});
$port3->on('beforehandShakeResponse', function($request, $response) {});
var_dump($port1->getCallback('handShake') != null);
var_dump($port1->getCallback('beforehandShakeResponse') != null);
echo 'DONE';
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
DONE
