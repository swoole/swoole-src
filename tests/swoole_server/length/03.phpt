--TEST--
swoole_server/length: 8M packet
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$port = get_one_free_port();

$size = 8 * 1024 * 1024;
$_g_data = random_bytes($size);

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($port, $pm, $size, $_g_data) {
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect(TCP_SERVER_HOST, $port, 1);
    $cli->send(pack('N', strlen($_g_data)) . $_g_data);
    $recv_data = $cli->recv();
    echo $recv_data;
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port, $size, $_g_data) {
    $serv = new Server(TCP_SERVER_HOST, $port);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 16 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("receive", function ($serv, $fd, $rid, $data) use ($size, $_g_data) {
        Assert::eq(strlen($data), $size + 4);
        Assert::eq($_g_data, substr($data, 4));
        $serv->send($fd, "OK\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
