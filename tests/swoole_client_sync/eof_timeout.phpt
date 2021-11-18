--TEST--
swoole_client_sync: eof timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

ini_set("swoole.display_errors", "Off");

$pm->initFreePorts(2);
$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
    if (!$cli->connect('127.0.0.1', $pm->getFreePort(1), 0.5)) {
        fail:
        echo "ERROR\n";
        Swoole\Process::kill($pid);
        return;
    }
    //no eof, should be timeout here
    if (!$cli->send("hello")) {
        goto fail;
    }
    $ret = $cli->recv();
    if (!$ret) {
        goto fail;
    }
    echo "OK\n";
    Swoole\Process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);

    $port2 = $http->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    $port2->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);

    $port2->on('Receive', function ($serv, $fd, $rid, $data) {
        $serv->send($fd, "Swoole: $data\r\n\r\n");
    });

    $http->set([
        //'log_file' => '/dev/null'
    ]);
    $http->on("WorkerStart", function (Swoole\Server $serv) {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end("OK\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
ERROR
