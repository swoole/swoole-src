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

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port, $pm, $size) {
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect(TCP_SERVER_HOST, $port, 1);
    $data = str_repeat('A', $size);
    $cli->send(pack('N', strlen($data)) . $data);
    $recv_data = $cli->recv();
    echo $recv_data;
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port, $size) {
    $serv = new \swoole_server(TCP_SERVER_HOST, $port);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 16 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("receive", function ($serv, $fd, $rid, $data) use ($size) {
        assert(strlen($data) == $size + 4);
        $serv->send($fd, "OK\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
