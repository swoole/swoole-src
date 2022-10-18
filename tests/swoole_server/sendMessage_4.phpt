--TEST--
swoole_server: send message [4]
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('Waiting for php to fix the problem with the serialization function. https://externals.io/message/118813');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof' => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    echo $client->recv();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $serv->set([
        'log_file' => '/dev/null',
        'worker_num' => 2,
    ]);
    $serv->on("workerStart", function ($serv, $wid) use ($pm) {
        if ($wid == 0) {
            $pm->wakeup();
        }
    });
    $serv->on('connect', function (Swoole\Server $serv, $fd) {
        $wid = $serv->getWorkerId();
        $serv->sendMessage([
            'fd' => $fd,
            'worker_id' => $wid,
            'exception' => new \Exception(__METHOD__),
        ], 1 - $wid);
    });
    $serv->on('receive', function ($serv, $fd, $reactor_id, $data) {

    });
    $serv->on('pipeMessage', function (Swoole\Server $serv, $worker_id, $data) {
        $serv->send($data['fd'], "OK\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
