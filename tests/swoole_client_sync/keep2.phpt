--TEST--
swoole_client_sync: long connection[2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';


$client1 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
$r = @$client1->connect(TCP_SERVER_HOST, 9999, 0.5);
Assert::false($r);
@$client1->close();

$client2 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
$r = @$client2->connect(TCP_SERVER_HOST, 9999, 0.5);
Assert::false($r);

Assert::same($client1->sock, $client2->sock);

?>
--EXPECT--
