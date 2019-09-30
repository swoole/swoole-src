--TEST--
swoole_server: pid_file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const PID_FILE = __DIR__.'/test.pid';
$pm = new SwooleTest\ProcessManager;
use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

$pm->parentFunc = function ($pid)
{
    Assert::assert(is_file(PID_FILE));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'pid_file' => PID_FILE,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
clearstatcache();
Assert::assert(!is_file(PID_FILE));
?>
--EXPECT--
