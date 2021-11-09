--TEST--
swoole_server: set max_concurrency
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
		go(function () use ($pm) {
		    $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
		    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
		        exit("connect failed\n");
		    }
		    $client->send("Hello world");
		    $data = $client->recv();
		    Assert::eq($data, "Hello world");
		});
    });
    echo "SUCCESS\n";
    $pm->kill();
};

$pm->childFunc = function () {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 2,
        'log_file' => TEST_LOG_FILE,
        'max_concurrency' => 10
    ]);
    $serv->on(EVENT_CONNECT, function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_RECEIVE, function (Server $serv, $fd, $reactor_id) {
        $serv->send($fd, $data);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
ALL DONE