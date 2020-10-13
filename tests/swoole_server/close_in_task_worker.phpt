--TEST--
swoole_server: close in task worker
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;

$pm = new SwooleTest\ProcessManager;

$socket = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_DGRAM, 0);

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP );
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("close");
        $data = $client->recv();
        Assert::string($data);
        Assert::length($data, 0);
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();

    global $socket;
    $result[] = fgets($socket[1]);
    $result[]  = fgets($socket[1]);

    Assert::eq($result[0], $result[1]);
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'log_file' => TEST_LOG_FILE,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
        global $socket;
        fwrite($socket[0], $serv->worker_id . "\n");
        $serv->task(['close_fd' => $fd, 'worker_id' => $serv->worker_id]);
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id) {
        global $socket;
        fwrite($socket[0], $serv->worker_id . "\n");
    });
    $serv->on(Constant::EVENT_TASK, function (Server $serv, $task_id, $worker_id, $msg) {
        Assert::true($serv->close($msg['close_fd']));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
