--TEST--
swoole_client_sync: discard pooled connections after incomplete I/O
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

function checkDiscard($server, int $port, array $settings, callable $transfer): void
{
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP);
    if ($settings) {
        Assert::true($client->set($settings));
    }
    Assert::true($client->connect('127.0.0.1', $port, 0.1));
    $peer = stream_socket_accept($server, 2);
    Assert::resource($peer);
    $transfer($client, $peer);
    Assert::true($client->close());

    Assert::true($client->connect('127.0.0.1', $port, 2));
    Assert::false($client->reuse);
    $replacement = stream_socket_accept($server, 2);
    Assert::resource($replacement);
    Assert::true($client->close(true));
    fclose($replacement);
    fclose($peer);
}

checkDiscard($server, $port, [], static function (Client $client, $peer): void {
    Assert::same(fwrite($peer, 'ab'), 2);
    Assert::false(@$client->recv(4, Client::MSG_WAITALL));
});

checkDiscard($server, $port, ['open_eof_check' => true, 'package_eof' => "\n"], static function (Client $client, $peer): void {
    Assert::same(fwrite($peer, 'ab'), 2);
    Assert::false(@$client->recv());
});

$lengthSettings = ['open_length_check' => true, 'package_body_offset' => 4];
foreach (["\0\0", pack('N', 4) . 'ab'] as $prefix) {
    checkDiscard($server, $port, $lengthSettings, static function (Client $client, $peer) use ($prefix): void {
        Assert::same(fwrite($peer, $prefix), strlen($prefix));
        Assert::false(@$client->recv());
    });
}

checkDiscard($server, $port, ['socket_buffer_size' => 4096], static function (Client $client, $peer): void {
    Assert::false(@$client->send(str_repeat('x', 8 * 1024 * 1024)));
    stream_set_timeout($peer, 2);
    Assert::same(fread($peer, 1), 'x');
});

fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
