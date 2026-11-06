--TEST--
swoole_client_async: a sendfile range starting at the end of the file completes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Async\Client;

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->on('connect', function (Client $client) {
        Assert::true($client->sendfile(__FILE__, filesize(__FILE__)));
        Assert::same($client->send('after'), 5);
    });
    $client->on('receive', function (Client $client, string $data) {
        Assert::same($data, 'after');
        $client->close();
    });
    $client->on('error', function () {
        echo "error\n";
    });
    $client->on('close', function () {
        echo "close\n";
    });
    $client->connect('127.0.0.1', $pm->getFreePort(), 1);
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $conn = stream_socket_accept($server, 5);
    stream_set_timeout($conn, 5);
    // The empty range sends nothing, and the data queued after it follows.
    Assert::same(fread($conn, 1024), 'after');
    fwrite($conn, 'after');
    stream_get_contents($conn);
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
echo "DONE\n";
?>
--EXPECT--
close
DONE
