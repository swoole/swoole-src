--TEST--
swoole_client_coro: reconnect 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Coroutine\Client;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $flag = 0;
        $client = new Client(SWOOLE_SOCK_TCP);

        $n = 2;
        while ($n--) {
            Assert::true($client->connect('127.0.0.1', 9501));
            Assert::true($client->close());
        }
        echo "DONE\n";
    });

    $pm->kill();

};
$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', 9501);
    $serv->set([
        'log_file' => '/dev/null',
    ]);
    $serv->on('start', function () use ($pm) {
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
DONE
