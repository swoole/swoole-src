--TEST--
swoole_client_async: eof protocol [async] [close]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'open_eof_split' => true, "package_eof" => "\r\n\r\n"]);

    $client->on("connect", function (Swoole\Async\Client $cli) {
        $cli->send("recv\r\n\r\n");
    });

    $client->on("receive", function (Swoole\Async\Client $cli, $pkg) use ($pid, $pm) {
        echo "RECEIVED\n";
        $cli->close();
        $pm->kill();
    });

    $client->on("error", function (Swoole\Async\Client $cli) {
        print("error");
    });

    $client->on("close", function (Swoole\Async\Client $cli) {
        echo "CLOSED\n";
    });

    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 0.5, 0)) {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'package_max_length' => 1024 * 1024 * 2, //2M
        'socket_buffer_size' => 128 * 1024 * 1024,
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        $serv->send($fd, str_repeat('A', rand(100, 2000)) . "\r\n\r\n");
    });
    $serv->start();
};
$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
RECEIVED
CLOSED
