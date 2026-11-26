--TEST--
swoole_client_sync: discard connections with unread buffered or socket data
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
$type = SWOOLE_SOCK_TCP | SWOOLE_KEEP;

foreach ([true, false] as $useEof) {
    $client = new Client($type);
    if ($useEof) {
        Assert::true($client->set(['open_eof_check' => true, 'package_eof' => "\r\n"]));
    }
    Assert::true($client->connect('127.0.0.1', $port, 2));
    $peer = stream_socket_accept($server, 2);
    Assert::resource($peer);
    Assert::same(fwrite($peer, "one\r\ntwo\r\n"), 10);
    if ($useEof) {
        Assert::same($client->recv(), "one\r\n");
    } else {
        $read = [$client];
        $write = $except = null;
        Assert::same(swoole_client_select($read, $write, $except, 2), 1);
    }
    Assert::true($client->close());

    $replacement = new Client($type);
    Assert::true($replacement->connect('127.0.0.1', $port, 2));
    Assert::false($replacement->reuse);
    $newPeer = stream_socket_accept($server, 2);
    Assert::resource($newPeer);
    Assert::true($replacement->close(true));
    fclose($peer);
    fclose($newPeer);
}

fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
