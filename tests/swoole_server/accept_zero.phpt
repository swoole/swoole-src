--TEST--
swoole_server: accept zero fd
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

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("stats");
        $data = $client->recv();
        $json = json_decode($data, true);
        Assert::eq($json[1], 1);
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => TEST_LOG_FILE,
    ]);
    $serv->on("Start", function ($serv) use ($pm) {
        fclose(STDIN);
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
        $serv->send($fd, json_encode(iterator_to_array($serv->connections))."\r\n");
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
