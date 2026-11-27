--TEST--
swoole_client_sync: a pooled socket retains its original TCP_NODELAY setting
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Client::class);
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use SwooleTest\Assert;

function tcpNodelay(Client $client): bool
{
    $stream = fopen('php://fd/' . $client->sock, 'r+');
    Assert::resource($stream);
    $socket = socket_import_stream($stream);
    $nodelay = socket_get_option($socket, SOL_TCP, TCP_NODELAY);
    fclose($stream);
    Assert::notSame($nodelay, false);
    // Some kernels return a flag mask instead of the literal integer 1 when enabled.
    return (bool) $nodelay;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
foreach ([false, true] as $enabled) {
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, $enabled ? 'nodelay' : 'nagle');
    $client->set(['open_tcp_nodelay' => $enabled]);
    Assert::true($client->connect('127.0.0.1', $port, 2));
    $peer = stream_socket_accept($server, 2);
    Assert::resource($peer);
    Assert::same(tcpNodelay($client), $enabled);
    Assert::true($client->close());

    $client->set(['open_tcp_nodelay' => !$enabled]);
    Assert::true($client->connect('127.0.0.1', $port, 2));
    Assert::true($client->reuse);
    Assert::same(tcpNodelay($client), $enabled);
    Assert::true($client->close(true));
    fclose($peer);
}

fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
