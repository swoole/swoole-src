--TEST--
swoole_server: last time
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\Run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $r = $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 1);
        Assert::assert($r);
        $cli->send("test1\r\ntest2\r\n");
        $result = [json_decode($cli->recv(), true), json_decode($cli->recv(), true)];
        Assert::lessThanEq($result[0]['php_time'] - $result[0]['last_dispatch_time'], 0.01);
        Assert::greaterThanEq($result[1]['php_time'] - $result[1]['last_dispatch_time'], 0.3);
        $cli->close();
        echo "SUCCESS\n";
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort());
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_eof_split' => true,
        'package_eof' => "\r\n",
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data) {
        $info = $serv->getClientInfo($fd);
        $info ['php_time'] = microtime(true);
        $serv->send($fd, json_encode($info));
        if (trim($data) == 'test1') {
            usleep(300000);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
