--TEST--
swoole_server: new twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Http\Server;
use Swoole\Event;

$pm = new SwooleTest\ProcessManager;

$atomic = new Swoole\Atomic();

$pm->parentFunc = function ($pid) use ($pm, $atomic) {
    posix_kill($atomic->get(), SIGINT);
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $http = new Server('0.0.0.0', 9501, SWOOLE_PROCESS);
    $http->set([
        Constant::OPTION_WORKER_NUM => 1
    ]);
    $http->on('WorkerStart', function () use ($pm, $http, $atomic) {
        if ($atomic->get() == 0) {
            $atomic->set(posix_getpid());
            Event::defer(function () use ($pm) {
                $pm->wakeup();
            });
            Swoole\Coroutine\System::waitSignal(SIGINT);
            var_dump($http->stop(waitEvent: true), $http->getLastError());
        } else {
            $pm->wakeup();
        }
    });
    $http->on('request', function () {
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(true)
int(0)
