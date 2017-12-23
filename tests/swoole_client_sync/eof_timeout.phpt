--TEST--
swoole_client_sync: eof timeout
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

$pm = new ProcessManager;

ini_set("swoole.display_errors", "Off");

$pm->parentFunc = function ($pid)
{
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
    if (!$cli->connect('127.0.0.1', 9502, 0.5))
    {
        fail:
        echo "ERROR\n";
        swoole_process::kill($pid);
        return;
    }
    //no eof, should be timeout here
    if (!$cli->send("hello"))
    {
        goto fail;
    }
    $ret = $cli->recv();
    if (!$ret)
    {
        goto fail;
    }
    echo "OK\n";
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);

    $port2 = $http->listen('127.0.0.1', 9502, SWOOLE_SOCK_TCP);
    $port2->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);

    $port2->on('Receive', function ($serv, $fd, $rid, $data)
    {
        $serv->send($fd, "Swoole: $data\r\n\r\n");
    });

    $http->set(array(
        //'log_file' => '/dev/null'
    ));
    $http->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response)
    {
        $response->end("OK\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
ERROR
