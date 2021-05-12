--TEST--
swoole_server: client close in writable event
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Client;
use Swoole\Constant;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 128 * 1024]);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    $client->send("begin");
    $pm->wait();
    usleep(100000);
    $client->close();
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'kernel_socket_send_buffer_size' => 128 * 1024,
        'buffer_output_size' => 4 * 1024 * 1024,
    ]);
    $serv->on(Constant::EVENT_WORKER_START, function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_CONNECT, function (Server $serv, $fd, $reactor_id) {
        echo "CONNECT $fd\n";
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) use ($pm) {
        $n = 8;
        $serv->pause($fd);
        while ($n--) {
            $serv->send($fd, str_repeat('A', 2 * 1024 * 1024) . "\r\n");
        }
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id)  use ($pm) {
        echo "CLOSE $fd\n";
        $pm->wakeup();
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
echo 'DONE'.PHP_EOL;
?>
--EXPECT--
CONNECT 1
CLOSE 1
DONE
