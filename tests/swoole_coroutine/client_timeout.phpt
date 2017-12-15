--TEST--
swoole_coroutine: timeout of udp client
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

$pm = new ProcessManager;

$pm->parentFunc = function ($pid)
{
    $data = curlGet("http://127.0.0.1:9501/");
    echo $data;
    swoole_process::kill($pid);
};


$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
    $http->set(array(
        'log_file' => '/dev/null'
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
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $begin = time();
        if (!$cli->connect('127.0.0.1', 9502, 3))
        {
            fail:
            $response->end("ERROR\n");
            return;
        }
        if (!$cli->send("hello"))
        {
            goto fail;
        }
        $ret = $cli->recv();
        $interval = time() - $begin;
        if ($ret !== false)
        {
            goto fail;
        }
        if ($interval < 3)
        {
            goto fail;
        }
        $cli->close();
        $response->end("TIMEOUT\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
TIMEOUT
