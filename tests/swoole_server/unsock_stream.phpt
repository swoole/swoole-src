--TEST--
swoole_server: unix socket stream server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new \swoole_client(SWOOLE_SOCK_UNIX_STREAM, SWOOLE_SOCK_SYNC);
    $r = $client->connect(UNIXSOCK_PATH, 0, -1);
    if ($r === false) {
        echo "ERROR";
        exit;
    }
    $client->send("SUCCESS");
    usleep(100 * 1000);
    echo $client->recv() . "\n";
    $client->close();
    @unlink(UNIXSOCK_PATH);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new \swoole_server(UNIXSOCK_PATH, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data) {
        $serv->send($fd, 'SUCCESS');
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
