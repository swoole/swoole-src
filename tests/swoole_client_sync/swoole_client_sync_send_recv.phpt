--TEST--
swoole_client_sync: udp sync client send & recv

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/simple_udp_server.php";
start_server($simple_tcp_server, UDP_SERVER_HOST, UDP_SERVER_PORT);

$client = new swoole_client(SWOOLE_SOCK_UDP);
$client->connect(UDP_SERVER_HOST, UDP_SERVER_PORT);

$data = "UdpSendto";
$client->send($data);

$message = $client->recv();
echo "FromServer:$message\n";
echo "SUCCESS";

?>

--EXPECTF--
FromServer:UdpSendto
SUCCESS
