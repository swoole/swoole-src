--TEST--
swoole_server: sendto timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 65507;

define('SOCK_FILE', __DIR__.'/server.sock');
swoole_async_set(['socket_send_timeout' => 0.5]);
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC);
    if (!$client->connect(SOCK_FILE, 0, 0.5)) {
        exit("connect failed\n");
    }
    $client->send(str_repeat('A', N));
    $s = microtime(true);
    $pm->wait();
    Assert::lessThan(microtime(true) - $s, 0.6);
    $data = $client->recv();
    Assert::same(strlen($data), N);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server(SOCK_FILE, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_DGRAM);
    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('packet', function ($serv, $data, $client) use ($pm) {
        while (true) {
            $re = $serv->send($client['address'], str_repeat('B', strlen($data)));
            if ($re == false) {
                break;
            }
        }
        $pm->wakeup();
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
