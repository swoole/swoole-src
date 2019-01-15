--TEST--
swoole_client_sync: long connection

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';


$client1 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
$r = @$client1->connect(TCP_SERVER_HOST, 9999, 0.5);
assert($r === false);

$client2 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
$r = @$client2->connect(TCP_SERVER_HOST, 9999, 0.5);
assert($r === false);

$client1->close(true);
$client2->close(true);

?>
--EXPECT--
