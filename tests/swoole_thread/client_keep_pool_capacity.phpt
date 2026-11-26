--TEST--
swoole_thread: the named Client pool bounds the number of idle connections
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_class_not_exist(Swoole\Client::class);
skip_if_function_not_exist('posix_getrlimit');
$limit = posix_getrlimit()['soft openfiles'];
skip('requires at least 64 file descriptors', is_int($limit) && $limit < 64);
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use SwooleTest\Assert;

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$descriptorLimit = posix_getrlimit()['soft openfiles'];
$capacity = is_int($descriptorLimit) ? min(1024, intdiv($descriptorLimit, 4)) : 1024;

$peers = [];
for ($n = 0; $n <= $capacity; $n++) {
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, "capacity-$n");
    Assert::true($client->connect('127.0.0.1', $port, 2));
    $peer = stream_socket_accept($server, 2);
    Assert::resource($peer);
    Assert::true($client->close());
    $peers[] = $peer;
}

// The pool preserves idle entries up to its limit and closes the surplus socket.
$lastPeer = $peers[$capacity];
stream_set_timeout($lastPeer, 2);
Assert::same(fread($lastPeer, 1), '');
Assert::true(feof($lastPeer));
$client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, 'capacity-0');
Assert::true($client->connect('127.0.0.1', $port, 2));
Assert::true($client->reuse);
Assert::true($client->close(true));

foreach ($peers as $peer) {
    fclose($peer);
}
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
