--TEST--
swoole_client_sync: endpoint and ID select the pool, and incompatible sockets are skipped
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Client::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use SwooleTest\Assert;

function port($server): int
{
    Assert::resource($server);
    return (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
}

function connectClient(int $port, array $options, string $id = 'same-id'): Client
{
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, $id);
    Assert::true($client->set($options));
    Assert::true($client->connect('127.0.0.1', $port, 2));
    return $client;
}

function connectUdpClient(int $port, int $flags, string $id = 'same-id'): Client
{
    $client = new Client(SWOOLE_SOCK_UDP | SWOOLE_KEEP, false, $id);
    Assert::true($client->set(['bind_address' => '127.0.0.1']));
    Assert::true($client->connect('127.0.0.1', $port, 2, $flags));
    return $client;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
$otherServer = stream_socket_server('tcp://127.0.0.1:0');
$port = port($server);
$settings = ['socket_buffer_size' => 8192, 'open_tcp_nodelay' => true];
$client = connectClient($port, $settings);
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
Assert::true($client->close());

$other = connectClient(port($otherServer), $settings);
Assert::false($other->reuse);
Assert::true($other->close(true));

$otherSettings = ['open_tcp_nodelay' => false, 'socket_buffer_size' => 4096];
$other = connectClient($port, $otherSettings, 'different-id');
Assert::false($other->reuse);
$otherPeer = stream_socket_accept($server, 2);
Assert::resource($otherPeer);
Assert::true($other->close(true));
fclose($otherPeer);

$client = connectClient($port, $otherSettings);
Assert::true($client->reuse);
Assert::true($client->close(true));
fclose($peer);
fclose($otherServer);
fclose($server);

$udpServer = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
$udpPort = port($udpServer);
$udp = connectUdpClient($udpPort, 0);
Assert::true($udp->close());

$udp = connectUdpClient($udpPort, 1);
Assert::false($udp->reuse);
Assert::true($udp->close(true));

$udp = connectUdpClient($udpPort, 2);
Assert::true($udp->reuse);
Assert::true($udp->close(true));

// TCP and UDP can bind the same numeric port and must each find their own idle socket.
$tcpServer = stream_socket_server("tcp://127.0.0.1:$udpPort");
Assert::resource($tcpServer);
$udp = connectUdpClient($udpPort, 0, '');
Assert::true($udp->close());
$tcp = connectClient($udpPort, [], '');
Assert::false($tcp->reuse);
$peer = stream_socket_accept($tcpServer, 2);
Assert::resource($peer);
Assert::true($tcp->close());

$tcp = connectClient($udpPort, [], '');
Assert::true($tcp->reuse);
Assert::true($tcp->close(true));
$udp = connectUdpClient($udpPort, 0, '');
Assert::true($udp->reuse);
Assert::true($udp->close(true));
fclose($peer);
fclose($tcpServer);
fclose($udpServer);
echo "DONE\n";
?>
--EXPECT--
DONE
