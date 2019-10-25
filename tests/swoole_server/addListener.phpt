--TEST--
swoole_server: addlistener
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";

use Swoole\Server;

$port1 = get_one_free_port();

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) {
    Co\Run(function () {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $r = $cli->connect(UDP_SERVER_HOST, UDP_SERVER_PORT, 1);
        Assert::assert($r);
        $cli->send("test");
        $i = $cli->getpeername();
        Assert::assert($i !== false);
        $cli->send('shutdown');
        $cli->close();
        echo "SUCCESS\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(UDP_SERVER_HOST, UDP_SERVER_PORT, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Packet", function (Server $serv, $data, $clientInfo) {
        if (trim($data) == 'shutdown') {
            $serv->shutdown();
            return;
        }
        $serv->sendto($clientInfo['address'], $clientInfo['port'], $data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
