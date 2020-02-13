--TEST--
swoole_server: max_queued_bytes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();

const N = 1024 * 1024 * 10;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($port, $pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', $port)) {
        exit("connect failed\n");
    }

    $bytes = 0;
    while ($bytes < N) {
        $write_n = $client->send(random_bytes(rand(1000, 80000)));
        if ($write_n == false) {
            break;
        } else {
            $bytes += $write_n;
        }
    }
    Assert::assert($bytes > N);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port) {
    $serv = new Swoole\Server('127.0.0.1', $port);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'max_queued_bytes' => 1024*1024,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $reactor_id, $data) {
        usleep(1000);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
