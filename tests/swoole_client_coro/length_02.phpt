--TEST--
swoole_client_coro: (length protocol) wrong packet
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($pm, $port)
{
    go(function () use ($port) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->set([
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ]);
        $cli->connect('127.0.0.1', $port);
        $data = str_repeat('A', 1025);
        $cli->send(pack('N', strlen($data)).$data);
        $retData = $cli->recv();
        Assert::same($retData, '');
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port) {
    $serv = new swoole_server('127.0.0.1', $port, SWOOLE_BASE);
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
        $serv->send($fd, pack('N', 1223));
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
