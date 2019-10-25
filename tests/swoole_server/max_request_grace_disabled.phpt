--TEST--
swoole_server: max_request_grace disabled
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'open_eof_check' => true,
        'package_eof' => "\n",
    ]);
    Assert::assert($client->connect('127.0.0.1', $pm->getFreePort(), -1));
    for ($i = 0; $i < 48; $i++) {
        $client->send("request $i\n");
        echo $client->recv();
    }
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'worker_num'        => 2,
        'dispatch_mode'     => 1,
        'max_request'       => 12,
        'max_request_grace' => 0,
        'open_eof_check'    => true,
        'package_eof'       => "\n",
        'log_file'          => '/dev/null',
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $count = 0;
    $serv->on('receive', function (swoole_server $serv, $fd, $reactorId, $data) use (&$count) {
        $count++;
        $serv->send($fd, "Worker $serv->worker_id served $count request(s) since start\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
Worker 0 served 1 request(s) since start
Worker 1 served 1 request(s) since start
Worker 0 served 2 request(s) since start
Worker 1 served 2 request(s) since start
Worker 0 served 3 request(s) since start
Worker 1 served 3 request(s) since start
Worker 0 served 4 request(s) since start
Worker 1 served 4 request(s) since start
Worker 0 served 5 request(s) since start
Worker 1 served 5 request(s) since start
Worker 0 served 6 request(s) since start
Worker 1 served 6 request(s) since start
Worker 0 served 7 request(s) since start
Worker 1 served 7 request(s) since start
Worker 0 served 8 request(s) since start
Worker 1 served 8 request(s) since start
Worker 0 served 9 request(s) since start
Worker 1 served 9 request(s) since start
Worker 0 served 10 request(s) since start
Worker 1 served 10 request(s) since start
Worker 0 served 11 request(s) since start
Worker 1 served 11 request(s) since start
Worker 0 served 12 request(s) since start
Worker 1 served 12 request(s) since start
Worker 0 served 1 request(s) since start
Worker 1 served 1 request(s) since start
Worker 0 served 2 request(s) since start
Worker 1 served 2 request(s) since start
Worker 0 served 3 request(s) since start
Worker 1 served 3 request(s) since start
Worker 0 served 4 request(s) since start
Worker 1 served 4 request(s) since start
Worker 0 served 5 request(s) since start
Worker 1 served 5 request(s) since start
Worker 0 served 6 request(s) since start
Worker 1 served 6 request(s) since start
Worker 0 served 7 request(s) since start
Worker 1 served 7 request(s) since start
Worker 0 served 8 request(s) since start
Worker 1 served 8 request(s) since start
Worker 0 served 9 request(s) since start
Worker 1 served 9 request(s) since start
Worker 0 served 10 request(s) since start
Worker 1 served 10 request(s) since start
Worker 0 served 11 request(s) since start
Worker 1 served 11 request(s) since start
Worker 0 served 12 request(s) since start
Worker 1 served 12 request(s) since start
