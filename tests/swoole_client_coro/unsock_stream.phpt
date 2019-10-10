--TEST--
swoole_client_coro: unix socket stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;
use Swoole\Coroutine\Client;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\Run(function (){
        $client = new Client(SWOOLE_SOCK_UNIX_STREAM);
        $r = $client->connect(UNIXSOCK_PATH, 0, -1);
        if ($r === false) {
            echo "ERROR";
            exit;
        }
        $client->send("SUCCESS");
        usleep(100 * 1000);
        echo $client->recv() . "\n";
        $client->close();
    });
    @unlink(UNIXSOCK_PATH);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(UNIXSOCK_PATH, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data) {
        $serv->send($fd, 'SUCCESS');
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
