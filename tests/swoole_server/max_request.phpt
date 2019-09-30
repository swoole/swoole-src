--TEST--
swoole_server: max_request
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
$counter = new swoole_atomic();

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set([
            "open_eof_check" => true,
            "open_eof_split" => true,
            "package_eof" => "\r\n\r\n",
        ]);
        $r = $client->connect('127.0.0.1', $pm->getFreePort(), -1);
        if ($r === false) {
            echo "ERROR";
            exit;
        }
        for ($i = 0; $i < 4000; $i++) {
            $data = "PKG-$i" . str_repeat('A', rand(100, 20000)) . "\r\n\r\n";
            if ($client->send($data) === false) {
                echo "send error\n";
                break;
            }
            $ret = $client->recv();
            Assert::same(strlen($ret), strlen($data) + 8);
        }
        $client->close();
    });

    Event::wait();

    global $counter;
    Assert::assert($counter->get() > 10);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => 4,
        'dispatch_mode' => 1,
        "open_eof_split" => true,
        "package_eof" => "\r\n\r\n",
        'max_request' => 200,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        global $counter;
        $counter->add(1);
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data)
    {
        $serv->send($fd, "Server: $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
