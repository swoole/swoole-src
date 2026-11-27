--TEST--
swoole_client_coro: implicit and explicit close release the Socket safely
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager();
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('Receive', function ($server, $fd, $rid, $data) { $server->send($fd, $data); });
    $server->start();
};
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        for ($i = 0; $i < 32; ++$i) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
            Assert::same($client->send('hello'), 5);
            Assert::same($client->recv(), 'hello');
            $weak = WeakReference::create($client->socket);
            if ($i % 2) {
                Assert::true($client->close());
                Assert::null($client->socket);
                Assert::null($weak->get());
            }
            unset($client);
            Assert::null($weak->get());
        }
    });
    $pm->kill();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
