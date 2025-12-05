--TEST--
swoole_server: wrong eof setting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function () use ($pm) {
    switch_process();
    go(function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_eof_check' => true,
            'open_eof_split' => true,
            "package_eof" => "",
        ]);
        $client->connect('127.0.0.1', $pm->getFreePort());
        $client->send("Swoole\r\n\r\n");
    });
    Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $pm->wakeup();
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        "package_eof" => "",
        'open_eof_check' => true,
        'open_eof_split' => true,
        "worker_num" => 1
    ]);
    $serv->on('workerStart', function (Server $serv) use ($pm) {
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        $serv->send($fd, "hello {$data}\r\n\r\n");
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: %s: package_eof cannot be an empty string in %s on line %d

Fatal error: %s: package_eof cannot be an empty string in %s on line %d

--EXPECTF_85--
Fatal error: %s: package_eof cannot be an empty string in %s on line %d
Stack trace:
#0 [internal function]: Swoole\Server\Port->set(Array)
#1 %s(%d): Swoole\Server->set(Array)
#2 [internal function]: {closure:%s:%d}()
#3 %s/tests/include/lib/src/ProcessManager.php(%d): call_user_func(Object(Closure))
#4 %s/tests/include/lib/src/ProcessManager.php(%d): SwooleTest\ProcessManager->runChildFunc()
#5 [internal function]: SwooleTest\ProcessManager->{closure:SwooleTest\ProcessManager::run():298}(Object(Swoole\Process))
#6 %s/tests/include/lib/src/ProcessManager.php(%d): Swoole\Process->start()
#7 %s(%d): SwooleTest\ProcessManager->run()
#8 {main}

Fatal error: %s: package_eof cannot be an empty string in %s on line %d
Stack trace:
#0 %s(%d): Swoole\Coroutine\Client->connect('127.0.0.1', %d)
#1 [internal function]: {closure:{closure:%s:%d}:%d}()
#2 {main}

