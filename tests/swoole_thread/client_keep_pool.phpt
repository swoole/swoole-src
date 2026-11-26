--TEST--
swoole_thread: named Client pools transfer idle connections between threads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_class_not_exist(Swoole\Client::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Client;
use Swoole\Thread;
use SwooleTest\Assert;

function connectClient(int $port, string $id, int $frameLength, float $timeout = 2.0): Client
{
    $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP, false, $id);
    Assert::true($client->set([
        'open_length_check' => true,
        'package_length_func' => static fn (string $data): int => $frameLength,
    ]));
    Assert::true($client->connect('127.0.0.1', $port, $timeout));
    return $client;
}

$args = Thread::getArguments();
if ($args !== null) {
    [$port, $id, $forceClose] = $args;
    $client = connectClient($port, $id, 2);
    Assert::false($client->reuse);
    Assert::true($client->close($forceClose));
    return;
}

$server = stream_socket_server('tcp://127.0.0.1:0');
Assert::resource($server);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$thread = new Thread(__FILE__, $port, 'shared', false);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
$peer = stream_socket_accept($server, 2);
Assert::resource($peer);

// Borrow after the creating thread and its PHP request have exited.
$client = connectClient($port, 'shared', 4, 1.0);
Assert::true($client->reuse);
Assert::same($client->reuseCount, 1);
Assert::same(fwrite($peer, 'data'), 4);
Assert::same($client->recv(), 'data');

// A second borrower opens a fresh socket while the first one has exclusive ownership.
$thread = new Thread(__FILE__, $port, 'shared', true);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
$secondPeer = stream_socket_accept($server, 2);
Assert::resource($secondPeer);
Assert::true($client->close(true));

$thread = new Thread(__FILE__, $port, '', false);
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
$localPeer = stream_socket_accept($server, 2);
Assert::resource($localPeer);
stream_set_timeout($localPeer, 2);
Assert::same(fread($localPeer, 1), '');
Assert::true(feof($localPeer));
$client = connectClient($port, '', 4);
Assert::false($client->reuse);
Assert::true($client->close(true));

fclose($peer);
fclose($secondPeer);
fclose($localPeer);
fclose($server);
echo "DONE\n";
?>
--EXPECT--
DONE
