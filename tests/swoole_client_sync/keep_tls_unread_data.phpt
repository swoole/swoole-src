--TEST--
swoole_client_sync: discard TLS connections with data buffered by OpenSSL
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\Assert;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->childFirst();
$pm->childFunc = static function () use ($pm): void {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . 'server.crt',
        'ssl_key_file' => SSL_FILE_DIR . 'server.key',
    ]);
    $server->on('WorkerStart', static function () use ($pm): void {
        $pm->wakeup();
    });
    $server->on('Receive', static function (Server $server, int $fd): void {
        $server->send($fd, 'abc');
    });
    $server->start();
};
$pm->parentFunc = static function () use ($pm): void {
    $type = SWOOLE_SOCK_TCP | SWOOLE_SSL | SWOOLE_KEEP;
    try {
        $client = new Client($type);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 2));
        Assert::same($client->send('request'), 7);
        // OpenSSL retains the rest of the TLS record outside the socket's receive queue.
        Assert::same($client->recv(1), 'a');
        Assert::true($client->close());

        $replacement = new Client($type);
        Assert::true($replacement->connect('127.0.0.1', $pm->getFreePort(), 2));
        Assert::false($replacement->reuse);
        Assert::true($replacement->close(true));
    } finally {
        $pm->kill();
    }
};
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
