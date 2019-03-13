--TEST--
swoole_server: wrong eof setting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function () use ($pm) {
    switch_process();
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->set([
        'open_eof_check' => true,
        'open_eof_split' => true,
        "package_eof" => ''
    ]);
    $client->on('connect', function (swoole_client $cli) {
        $cli->send("Swoole\r\n\r\n");
    });
    $client->on('error', function () { });
    $client->on('close', function () { });
    $client->connect('127.0.0.1', $pm->getFreePort());
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $pm->wakeup();
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'package_eof' => '',
        'open_eof_check' => true,
        'open_eof_split' => true,
        "worker_num" => 1
    ]);
    $serv->on('workerStart', function (swoole_server $serv) use ($pm) { });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data) {
        $serv->send($fd, "hello {$data}\r\n\r\n");
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: %s: pacakge_eof cannot be an empty string in %s on line %d

Fatal error: %s: pacakge_eof cannot be an empty string in %s on line %d
