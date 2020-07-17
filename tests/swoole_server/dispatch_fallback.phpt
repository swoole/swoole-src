--TEST--
swoole_server: dispatch_fallback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const WORKER_N = 4;

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

global $stats;
$stats = array();
$count = 0;
$port = get_one_free_port();

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    global $count, $stats;
    for ($i = 0; $i < MAX_CONCURRENCY_MID; $i++)
    {
        go(function () use ($port) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'package_eof' => "\r\n\r\n",
                'open_eof_split' => true,
            ]);
            $r = $cli->connect(TCP_SERVER_HOST, $port, 1);
            Assert::assert($r);
            for ($i = 0; $i < MAX_REQUESTS; $i++)
            {
                $cli->send("hello world\r\n\r\n");
            }
            $cli->count = 0;
            for ($i = 0; $i < MAX_REQUESTS; $i++)
            {
                $data = $cli->recv();
                global $stats;
                $wid = trim($data);
                if (isset($stats[$wid]))
                {
                    $stats[$wid]++;
                }
                else
                {
                    $stats[$wid] = 1;
                }
                $cli->count++;
                if ($cli->count == MAX_REQUESTS)
                {
                    $cli->close();
                }
            }
        });
    }
    Event::wait();
    Swoole\Process::kill($pid);
    phpt_var_dump($stats);
    foreach ($stats as $s)
    {
        Assert::same($s, MAX_REQUESTS * MAX_CONCURRENCY_MID / WORKER_N);
    }
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new Server('127.0.0.1', $port, SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => WORKER_N,
        'dispatch_mode' => 1,
        'dispatch_func' => function ($serv, $fd, $type, $data) {
            return SWOOLE_DISPATCH_RESULT_USERFUNC_FALLBACK;
        },
        'package_eof' => "\r\n\r\n",
        'open_eof_split' => true,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {
        $serv->send($fd, $serv->worker_id . "\r\n\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
