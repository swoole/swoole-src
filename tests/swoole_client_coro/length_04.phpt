--TEST--
swoole_client_coro: (length protocol) no body
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = MAX_REQUESTS * 10;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->set([
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_type' => 'n',
            'package_length_offset' => 0,
            'package_body_offset' => 0,
        ]);
        $cli->connect('127.0.0.1', $pm->getFreePort());
        $cli->send(pack('n', 2));

        $count = N;
        while($count--)
        {
            $data = $cli->recv();
            $header = unpack('nlen', $data);
            Assert::same(strlen($data), 2);
            Assert::same($header['len'], 2);
        }
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        //'dispatch_mode'         => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'n',
        'package_length_offset' => 0,
        'package_body_offset' => 0,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $header = unpack('nlen', $data);
        Assert::same(strlen($data), 2);
        Assert::same($header['len'], 2);
        $count = N;
        while($count--)
        {
            $serv->send($fd, pack('n', 2));
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
