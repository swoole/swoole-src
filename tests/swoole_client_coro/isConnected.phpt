--TEST--
swoole_client_coro: is connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\ProcessManager;
use Swoole\Server;
use Swoole\Event;
use Swoole\Coroutine\Client;

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Client(SWOOLE_SOCK_TCP);
        Assert::false($cli->isConnected());
        if (!$cli->connect('127.0.0.1', $pm->getFreePort())) {
            echo "ERROR\n";
        }
        Assert::true($cli->isConnected());
        $cli->close();
        Assert::false($cli->isConnected());
        $pm->kill();
    });
    Event::wait();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $serv->set(array(
        'log_file' => '/dev/null'
    ));
    $serv->on("WorkerStart", function (Server $serv) {
        global $pm;
        $pm->wakeup();
    });
    $serv->on('Receive', function () {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
