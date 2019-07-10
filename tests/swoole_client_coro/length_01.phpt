--TEST--
swoole_client_coro: (length protocol) wrong packet
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->set([
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ]);
        $cli->connect('127.0.0.1', $pm->getFreePort());
        $data = str_repeat('A', 1025);
        $cli->send(pack('N', strlen($data)) . $data);
        $retData = $cli->recv();
        Assert::assert($retData != false);
        $len = unpack('Nlen', $retData)['len'];
        Assert::same(strlen($retData), $len + 4);
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
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $len = rand(512*1024, 1024*1024 - 4);
        $data = pack('N',$len ).str_repeat('C', $len);
        $chunks = str_split($data, 8192 * 16);
        foreach ($chunks as $c) {
            $serv->send($fd, $c);
            usleep(rand(10000, 99999));
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
