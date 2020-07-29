--TEST--
swoole_client_coro: unix socket dgram
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Coroutine\Client;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\Run(function () {
        $client = new Client(SWOOLE_SOCK_UNIX_DGRAM);
        $client->set([
            'bind_address' => __DIR__ . '/client.sock',
            'bind_port' => 0,
        ]);
        $r = $client->connect(UNIXSOCK_PATH, 0, -1);
        if ($r === false) {
            echo "ERROR";
            exit;
        }
        $client->send("SUCCESS");
        echo $client->recv();
        $client->close();
    });
    @unlink(UNIXSOCK_PATH);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(UNIXSOCK_PATH, 0, SWOOLE_PROCESS, SWOOLE_SOCK_UNIX_DGRAM);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null',]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("packet", function (Server $serv, $data, $addr) {
        $serv->send($addr['address'], 'SUCCESS'.PHP_EOL);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
SUCCESS
