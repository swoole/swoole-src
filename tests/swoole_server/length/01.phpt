--TEST--
swoole_server/length: big packet
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
if (!is_file('/proc/sys/net/core/wmem_max')) {
    exit('skip not linux');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$port = get_one_free_port();

use Swoole\Server;
use SwooleTest\ProcessManager;
use Swoole\Atomic;
use Swoole\Client;

$max = file_get_contents('/proc/sys/net/core/wmem_max');
$max = min(8 * 1024 * 1024, $max);

$size = intval($max) * 2 - 32 - 4;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($port, $pm, $size) {
    $cli = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect(TCP_SERVER_HOST, $port, 1);
    $data = str_repeat('A', $size);
    $cli->send(pack('N', strlen($data)) . $data);
    $recv_data = $cli->recv();
    echo $recv_data;
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port, $size) {
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
    $serv->on("receive", function ($serv, $fd, $rid, $data) use ($size) {
        Assert::assert(strlen($data) == $size + 4);
        $serv->send($fd, "OK\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
