--TEST--
swoole_client_coro: #2346 method timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_eof_split' => false,
            'open_length_check' => true,
            'package_length_type' => 'N',
            'package_length_offset' => 4,
            'package_body_offset' => 8,
            'package_max_length' => 2 * 1024 * 1024
        ]);
        if ($client->connect('127.0.0.1', $pm->getFreePort(), 0.1)) {
            // 0.2
            $s = microtime(true);
            Assert::assert(@!$client->recv(0.2));
            Assert::same($client->errCode, SOCKET_ETIMEDOUT);
            approximate(0.2, microtime(true) - $s);
            // -1 & 0.3
            go(function () use ($client) {
                co::sleep(0.3);
                $client->close();
            });
            Assert::assert(@!$client->recv(-1)); // connection closed
            Assert::same($client->errCode, SOCKET_ECONNRESET);
            approximate(0.5, microtime(true) - $s);
            // canceled
            echo "DONE\n";
        }
    });
    swoole_event_wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
