--TEST--
swoole_server: max_idle_time
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Atomic;
use Swoole\Client;

define('SOCK_FILE', __DIR__.'/server.sock');
$pm = new SwooleTest\ProcessManager;

$time1 = new Atomic(0);
$time2 = new Atomic(0);

$pm->parentFunc = function ($pid) use ($pm, $time1, $time2) {
    $client = new Client(SWOOLE_SOCK_UNIX_STREAM, SWOOLE_SOCK_SYNC);
    if (!$client->connect(SOCK_FILE, 0, 0.5)) {
        exit("connect failed\n");
    }
    $socket = $client->getSocket();
    socket_set_option($socket, SOL_SOCKET, SO_SNDBUF, 65536);
    socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 65536);
    $client->send('hello world');
    $s = microtime(true);
    sleep(1);
    usleep(200000);
    Assert::greaterThan($time2->get() - $time1->get(), 1000);
    $result = '';
    while(true) {
        $data = $client->recv();
        if (empty($data)) {
            break;
        }
        $result .= $data;
    }
    Assert::greaterThan(strlen($result), 65536);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $time1, $time2) {
    $serv = new Server(SOCK_FILE, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
    $serv->set([
        'worker_num' => 1,
        'kernel_socket_send_buffer_size' => 65536,
        'log_file' => '/dev/null',
        'max_idle_time' => 1,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Receive', function ($serv, $fd, $tid, $data) use ($time1)  {
        $time1->set(microtime(true) * 1000);
        $serv->send($fd, str_repeat('A', 1024 * 1024 * 4));
    });
    $serv->on('close', function ($serv, $fd, $tid) use ($time2) {
        $time2->set(microtime(true) * 1000);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
