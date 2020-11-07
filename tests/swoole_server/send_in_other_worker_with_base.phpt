--TEST--
swoole_server: send data in another process with base mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        if ($cli->connect('127.0.0.1', $pm->getFreePort(), 100) == false) {
            echo "ERROR\n";
            return;
        }
        $data = base64_encode(random_bytes(128));
        $cli->send($data);
        Assert::same($cli->recv(), 'Swoole: '.$data);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 2,
        'log_file' => TEST_LOG_FILE,
    ));
    $serv->on("WorkerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_PIPE_MESSAGE, function ($serv, $workerId, $msg) {
        $serv->send($msg['fd'], 'Swoole: '.$msg['data']);
    });
    $serv->on(Constant::EVENT_RECEIVE, function (Swoole\Server $serv, $fd, $rid, $data) {
        $serv->sendMessage(['data' => $data, 'fd' => $fd], 1 - $serv->getWorkerId());
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
