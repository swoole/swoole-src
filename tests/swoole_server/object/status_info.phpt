--TEST--
swoole_server/object: status info
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Event;
use Swoole\Process;
use Swoole\Server;
use Swoole\Client;
use Swoole\Server\StatusInfo;
use Swoole\Timer;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 10) or die("ERROR");
    $cli->send("task-01") or die("ERROR");
    Assert::same($cli->recv(), "hello world");
    $cli->close();
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort());

    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'event_object' => true,
        'enable_coroutine' => false,
    ]);

    $serv->on("ManagerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
        Timer::after(100, function () use ($serv) {
            Process::kill($serv->getWorkerPid(0), SIGKILL);
        });
        Timer::after(200, function () use ($serv) {
            $serv->sendMessage("exit", 0);
            Timer::after(100, function () use ($serv) {
                $serv->send(1, 'hello world');
            });
        });
    });

    $serv->on(Constant::EVENT_PIPE_MESSAGE, function (Server $serv, $msg) {
        if ($msg->data == 'exit') {
            throw new RuntimeException("error");
        }
    });

    $serv->on("Receive", function (Server $serv, $event) {

    });

    $serv->on(Constant::EVENT_WORKER_ERROR, function (Server $serv, StatusInfo $info) {
        static $count = 0;
        $count++;
        if ($count == 1) {
            Assert::eq($info->signal, SIGKILL);
            Assert::eq($info->exit_code, 0);
        } elseif ($count == 2) {
            Assert::eq($info->signal, 0);
            Assert::eq($info->exit_code, 255);
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--

Fatal error: Uncaught RuntimeException: error in %s:%d
Stack trace:
#0 [internal function]: {closure}(Object(Swoole\Server), Object(Swoole\Server\PipeMessage))
#1 %s(%d): Swoole\Server->start()
#2 [internal function]: {closure}()
#3 %s(%d): call_user_func(Object(Closure))
#4 %s(%d): SwooleTest\ProcessManager->runChildFunc()
#5 [internal function]: SwooleTest\ProcessManager->SwooleTest\{closure}(Object(Swoole\Process))
#6 %s(%d): Swoole\Process->start()
#7 %s(%d): SwooleTest\ProcessManager->run()
#8 {main}
  thrown in %s on line %d
DONE
