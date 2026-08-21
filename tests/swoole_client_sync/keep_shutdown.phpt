--TEST--
swoole_client_sync: a persistent connection that was shut down is not reused
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// Nothing accepts this listener, so the peer cannot close the connection and send a FIN.
// The client socket stays connected and only its own shutdown state can make it unfit for reuse.
$server = stream_socket_server('tcp://' . TCP_SERVER_HOST . ':0', $errno, $errstr);
Assert::assert($server !== false, "$errstr ($errno)");
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

// An ordinary persistent connection is still pooled and handed back.
$client1 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
Assert::true($client1->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($client1->close());

$client2 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
Assert::true($client2->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($client2->reuse);
$client2->close(true);

// A connection that was shut down is not.
$client3 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
Assert::true($client3->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($client3->shutdown(Swoole\Client::SHUT_WR));
Assert::true($client3->close());

$client4 = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC);
Assert::true($client4->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::false($client4->reuse);

$client4->close(true);
fclose($server);
?>
--EXPECT--
