--TEST--
swoole_client_sync: pooled clients retain native framing and replace PHP callbacks
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

function connectClient(int $port, string $id, array $settings = []): Client
{
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, $id);
    if ($settings) {
        Assert::true($client->set($settings));
    }
    Assert::true($client->connect('127.0.0.1', $port, 0.5));
    return $client;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

$callback = static fn (string $data): int => 2;
$observer = WeakReference::create($callback);
$client = connectClient($port, 'callback', [
    'open_length_check' => true,
    'package_length_func' => $callback,
    'package_max_length' => 32,
]);
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
unset($callback);
$client->setting = [];
Assert::notNull($observer->get());
Assert::true($client->close());
Assert::null($observer->get());

$calls = 0;
$client = connectClient($port, 'callback', [
    'package_max_length' => 2,
    'package_length_func' => static function (string $data) use (&$calls): int {
        $calls++;
        return 6;
    },
]);
Assert::true($client->reuse);
Assert::same(fwrite($peer, 'abcdef'), 6);
Assert::same($client->recv(), 'abcdef');
Assert::greaterThan($calls, 0);
Assert::true($client->close());

$withoutCallback = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, 'callback');
try {
    $withoutCallback->connect('127.0.0.1', $port, 2);
    throw new RuntimeException('The pooled client requires a callback');
} catch (Swoole\Exception $e) {
    Assert::false($withoutCallback->isConnected());
}
fclose($peer);

$client = connectClient($port, 'eof', ['open_eof_check' => true, 'package_eof' => "\r\n"]);
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);
// A timed-out EOF read leaves an allocated buffer with zero bytes in it.
Assert::false(@$client->recv());
Assert::true($client->close());

$client = connectClient($port, 'eof', ['package_eof' => '!', 'package_length_type' => '?']);
Assert::true($client->reuse);
Assert::same(fwrite($peer, "line\r\n"), 6);
Assert::same($client->recv(), "line\r\n");
Assert::true($client->close(true));
fclose($peer);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
