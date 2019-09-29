--TEST--
swoole_server: addProcess
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
        $cli->send("test");
        $data = $cli->recv();
        Assert::same($data, 'test');
        $cli->send('shutdown');
        $cli->close();
        echo "SUCCESS\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort());
    $process = new \Swoole\Process(function ($process) use ($serv) {
        while (1) {
            $msg = json_decode($process->read(), true);
            $serv->send($msg['fd'], $msg['data']);
        }
    });
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data) use ($process) {
        if (trim($data) == 'shutdown') {
            $serv->shutdown();
            return;
        } else {
            $process->write(json_encode(['fd' => $fd, 'data' => $data]));
        }
    });
    $serv->addProcess($process);
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
