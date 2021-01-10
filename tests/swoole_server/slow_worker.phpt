--TEST--
swoole_server: slow worker
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

$atomic1 = new Swoole\Atomic(0);
$atomic2 = new Swoole\Atomic(0);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $atomic2) {
    $cli = new Client(SWOOLE_SOCK_TCP);
    $r = $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 5);
    Assert::assert($r);
    for ($i = 0; $i < MAX_REQUESTS; $i++) {
        $rand = rand(8 * 1024, 1024 * 1024);
        $data = pack('N', $rand) . str_repeat('A', $rand);
        $cli->send($data);
        $atomic2->add(strlen($data));
    }
    echo $cli->recv();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic1, $atomic2) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 16 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
        usleep(100000);
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($atomic1, $atomic2) {
        $atomic1->add(strlen($data));
        if ($atomic1->get() == $atomic2->get()) {
            $serv->send($fd, "DONE\n");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
