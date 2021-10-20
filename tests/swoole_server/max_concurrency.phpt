--TEST--
swoole_server: max_concurrency
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

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i=0; $i < 5; $i++) { 
        go(function () use ($pm, $i) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set([
                "open_eof_check" => true,
                "open_eof_split" => true,
                "package_eof" => "\r\n\r\n",
            ]);
            $r = $client->connect('127.0.0.1', $pm->getFreePort(), -1);
            $data = "$i\r\n\r\n";
            $client->send($data);
            $ret = $client->recv();
            var_dump(trim($ret));
            $client->close();
        });
    }
    
    Event::wait();

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    Co::set(['max_concurrency' => 1]);
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'dispatch_mode' => 1,
        'open_eof_split' => true,
        'package_eof' => "\r\n\r\n",
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data)
    {
        global $count;
        $count = 0;
        co::sleep(0.05);
        $count += 1;
        $serv->send($fd, "$count\r\n\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
string(1) "1"
string(1) "1"
string(1) "1"
string(1) "1"
string(1) "1"
