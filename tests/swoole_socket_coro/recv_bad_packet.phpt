--TEST--
swoole_socket_coro: recv bad packet
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const SIZE = 2 * 1024 * 1024;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < MAX_CONCURRENCY_MID; $i++) {
        go(function () use ($pm, $i) {
            $cli = new Co\Socket(AF_INET, SOCK_STREAM, 0);
            $cli->setProtocol([
                'open_length_check' => true,
                'package_max_length' => 4 * 1024 * 1024,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ]);
            if ($cli->connect('127.0.0.1', $pm->getFreePort()) == false) {
                echo "ERROR\n";
                return;
            }
            for ($i = 0; $i < 3; $i++) {
                $sid = strval(rand(100000, 999999));
                $send_data = str_repeat('A', 1000) . $sid;
                $cli->send(pack('N', strlen($send_data)) . $send_data);
                $data = $cli->recvPacket(0.2);
                Assert::isEmpty($data);
            }
        });
    }
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 4,
        'log_level' => SWOOLE_LOG_ERROR,
        'open_length_check' => true,
        'package_max_length' => 4 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ));
    $serv->on("WorkerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        $len = rand(1024, 8192);
        $send_data = str_repeat('A', $len);
        //bad packet
        $serv->send($fd, pack('N', SIZE) . $send_data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
