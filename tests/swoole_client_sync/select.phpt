--TEST--
swoole_client_sync: select
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

const TIMEOUT = 0.05;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $clients = [];

    for($i=0; $i< 4; $i++) {
        $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $ret = $client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0);
        if(!$ret) {
            echo "Connect Server fail.errCode=".$client->errCode;
        } else {
            $client->send("HELLO WORLD\n");
            $clients[$client->sock] = $client;
        }
    }
    
    $s = microtime(true);
    while (!empty($clients)) {
        $write = $error = array();
        $read = array_values($clients);
        $n = swoole_select($read, $write, $error, TIMEOUT);
        if ($n > 0) {
            foreach ($read as $index => $c) {
                echo "Recv #{$c->sock}: " . $c->recv() . "\n";
                unset($clients[$c->sock]);
            }
            continue;
        } else if ($n == 0) {
            echo "TIMEOUT\n";
        } else {
            echo "ERROR\n";
        }
        break;
    }

    Assert::greaterThanEq(microtime(true) - $s, TIMEOUT);

    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data) {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
TIMEOUT
