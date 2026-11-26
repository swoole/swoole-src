--TEST--
swoole_client_sync: a length callback can replace the current connection
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

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

$client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP);
$client->set([
    'open_length_check' => true,
    'package_length_func' => static function (string $data) use ($client, $port): int {
        Assert::false(@$client->recv());
        Assert::true($client->close(true));
        $client->setting = [];
        Assert::true($client->connect('127.0.0.1', $port, 2));
        return strlen($data);
    },
]);
Assert::true($client->connect('127.0.0.1', $port, 2));
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
Assert::same(fwrite($peer, 'frame'), 5);
Assert::false($client->recv());
Assert::true($client->isConnected());

$replacement = stream_socket_accept($server, 2);
Assert::resource($replacement);
Assert::same(fwrite($replacement, 'next'), 4);
Assert::same($client->recv(4, Client::MSG_WAITALL), 'next');
Assert::true($client->close(true));
fclose($replacement);
fclose($peer);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
