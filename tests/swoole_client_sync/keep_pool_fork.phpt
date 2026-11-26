--TEST--
swoole_client_sync: forked processes start with an empty Client connection pool
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use Swoole\Process;
use SwooleTest\Assert;

function connectClient(int $port): Client
{
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, 'fork-pool');
    Assert::true($client->connect('127.0.0.1', $port, 2));
    return $client;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$client = connectClient($port);
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
Assert::true($client->close());

$child = new Process(static function (Process $child) use ($port): void {
    Assert::true($child->setTimeout(5));
    $client = connectClient($port);
    $child->write($client->reuse ? 'reused' : 'fresh');
    Assert::true($client->close(true));
    Assert::same($child->read(), 'stop');
});
Assert::greaterThan($child->start(), 0);
Assert::true($child->setTimeout(2));

try {
    Assert::same($child->read(), 'fresh');
    $childPeer = stream_socket_accept($server, 2);
    Assert::resource($childPeer);

    $client = connectClient($port);
    Assert::true($client->reuse);
    Assert::same(fwrite($peer, 'alive'), 5);
    Assert::same($client->recv(5, Client::MSG_WAITALL), 'alive');
    Assert::true($client->close(true));

    // EOF must arrive while the child is still running, without an inherited client descriptor.
    stream_set_timeout($peer, 1);
    Assert::same(fread($peer, 1), '');
    Assert::true(feof($peer));
} finally {
    $child->write('stop');
    Assert::same(Process::wait()['code'], 0);
}
fclose($peer);
fclose($childPeer);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
