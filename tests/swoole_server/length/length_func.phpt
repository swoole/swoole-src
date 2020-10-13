--TEST--
swoole_server/length: package_length_func
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;

const LEN = 3;
const COUNT = 12;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 1);
    $data = str_repeat('A', LEN * COUNT);
    $cli->send($data);

    $data = '';
    while (1) {
        $recv_data = $cli->recv();
        if (!$recv_data) {
            break;
        }
        $data .= $recv_data;
        if (strlen($data) >= LEN * COUNT) {
            break;
        }
    }
    Assert::eq($data, str_repeat("OK\n", 12));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort());
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_body_offset' => 4,
        'package_length_func' => function(){
            return 3;
        }
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("receive", function ($serv, $fd, $rid, $data) {
        Assert::assert(strlen($data) == LEN);
        $serv->send($fd, "OK\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
