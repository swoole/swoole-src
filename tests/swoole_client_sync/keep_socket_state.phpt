--TEST--
swoole_client_sync: persistent pooling checks the client's own socket state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = stream_socket_server('tcp://' . TCP_SERVER_HOST . ':0', $errno, $errstr);
Assert::notSame($server, false, "$errstr ($errno)");
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$type = SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC;

$client = new Swoole\Client($type);
Assert::true($client->connect(TCP_SERVER_HOST, $port, 0.5));
$peer = stream_socket_accept($server, 1);
Assert::notSame($peer, false);

// A bound, non-listening port fails with ECONNREFUSED or ETIMEDOUT depending on the platform.
$refused = stream_socket_server('tcp://' . TCP_SERVER_HOST . ':0', $errno, $errstr, STREAM_SERVER_BIND);
Assert::notSame($refused, false, "$errstr ($errno)");
$refusedPort = (int) substr(strrchr(stream_socket_get_name($refused, false), ':'), 1);
$failed = new Swoole\Client(SWOOLE_SOCK_TCP | SWOOLE_SYNC);
Assert::false(@$failed->connect(TCP_SERVER_HOST, $refusedPort, 0.5));
Assert::true(in_array(swoole_last_error(), [SOCKET_ECONNREFUSED, SOCKET_ETIMEDOUT], true));
Assert::true($client->close());

$reused = new Swoole\Client($type);
Assert::true($reused->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($reused->reuse);
Assert::true($reused->close(true));
fclose($peer);
fclose($refused);

// A peer-closed connection is released immediately, without waiting for another pool lookup.
$client = new Swoole\Client($type);
Assert::true($client->connect(TCP_SERVER_HOST, $port, 0.5));
$peer = stream_socket_accept($server, 1);
Assert::notSame($peer, false);
fclose($peer);
Assert::same($client->recv(1, Swoole\Client::MSG_PEEK), '');
$fd = $client->sock;
Assert::true($client->close());
$probe = @fopen('php://fd/' . $fd, 'r');
if (is_resource($probe)) {
    fclose($probe);
}
Assert::false($probe, 'dead descriptor must be closed immediately');

fclose($server);
?>
--EXPECT--
