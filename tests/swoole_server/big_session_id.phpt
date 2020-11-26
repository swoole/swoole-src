--TEST--
swoole_server: big session id
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const N = 10;

define('START_SESSION_ID', 1 << 32 - 1);

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

global $count;
$count = 0;
$port = get_one_free_port();

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($port) {
    global $count;
    for ($i = 0; $i < N; $i++) {
        go(function () use ($port, $i) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            $r = $cli->connect(TCP_SERVER_HOST, $port, 1);
            Assert::assert($r);
            $data = $cli->recv();
            Assert::same($data, (START_SESSION_ID + 1 + $i) . "-OK");
            global $count;
            $count++;
            $cli->close();
        });
    }
    Event::wait();
    Assert::same($count, N);
    Swoole\Process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port) {
    $serv = new Server('127.0.0.1', $port, SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'start_session_id' => START_SESSION_ID,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (Server $serv, $fd, $rid) {
        global $count;
        $count++;
        if ($count == N) {
            $serv->defer(function () use ($serv) {
                foreach ($serv->connections as $fd) {
                    $serv->send($fd, "$fd-OK");
                }
            });
        }
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
