--TEST--
swoole_client_sync: reconnect resets reuse properties and recovers from invalid settings
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
Assert::true($client->connect('127.0.0.1', $port, 2));
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
Assert::true($client->close());

Assert::true($client->connect('127.0.0.1', $port, 2));
Assert::true($client->reuse);
Assert::same($client->reuseCount, 1);
Assert::true($client->close(true));
fclose($peer);

$client->set(['package_length_type' => '?']);
try {
    $client->connect('127.0.0.1', $port, 2);
    throw new RuntimeException('Invalid package_length_type was accepted');
} catch (Swoole\Exception $e) {
    Assert::false($client->isConnected());
}

$client->set(['package_length_type' => 'N']);
Assert::true($client->connect('127.0.0.1', $port, 2));
Assert::false($client->reuse);
Assert::same($client->reuseCount, 0);
$replacement = stream_socket_accept($server, 2);
Assert::resource($replacement);
Assert::true($client->close(true));
fclose($replacement);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
