--TEST--
swoole_client_sync: borrowed connections retain the original timeout
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

function connectClient(int $port, int $type, float $timeout, int $flags): Client
{
    $client = new Client($type | SWOOLE_KEEP);
    Assert::true($client->connect('127.0.0.1', $port, $timeout, $flags));
    return $client;
}

function checkReadTimeout(Client $client): void
{
    $started = hrtime(true);
    Assert::false(@$client->recv());
    $elapsed = (hrtime(true) - $started) / 1e9;
    Assert::greaterThanEq($elapsed, 0.08);
    Assert::lessThan($elapsed, 1.5);
}

swoole_async_set(['socket_read_timeout' => 4.0]);
foreach (['tcp' => SWOOLE_SOCK_TCP, 'udp' => SWOOLE_SOCK_UDP] as $scheme => $type) {
    $isTcp = $scheme === 'tcp';
    $server = stream_socket_server("$scheme://127.0.0.1:0", $errno, $errstr,
        $isTcp ? STREAM_SERVER_BIND | STREAM_SERVER_LISTEN : STREAM_SERVER_BIND);
    Assert::resource($server);
    $port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
    $flags = $isTcp ? 0 : 1;

    $client = connectClient($port, $type, 0.2, $flags);
    if ($isTcp) {
        $peer = stream_socket_accept($server, 2);
        Assert::resource($peer);
    }
    Assert::true($client->close());

    $client = connectClient($port, $type, 4.0, $flags);
    Assert::true($client->reuse);
    checkReadTimeout($client);

    if ($isTcp) {
        Assert::true($client->close());
        $client = connectClient($port, $type, 0.0, $flags);
        Assert::true($client->reuse);
        checkReadTimeout($client);
        fclose($peer);
    }
    Assert::true($client->close(true));
    fclose($server);
}
echo "DONE\n";
?>
--EXPECT--
DONE
