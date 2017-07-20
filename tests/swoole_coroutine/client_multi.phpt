--TEST--
swoole_coroutine: multi http client
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
        $cli1 = new Swoole\Coroutine\Http\Client('www.baidu.com', 443, true);
        $cli1->set(['timeout' => 1]);
        $cli1->setHeaders([
            'Host' => "www.baidu.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli1->setDefer(1);

        $cli2 = new Swoole\Coroutine\Http\Client('www.baidu.com', 443, true);
        $cli2->set(['timeout' => 1]);
        $cli2->setHeaders([
            'Host' => "www.baidu.com",
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli2->setDefer(1);

        $ret1 = ($cli1->get('/'));
        $ret2 = ($cli2->get('/'));
        if (!$ret1 or !$ret2)
        {
            $response->end("ERROR\n");
            return;
        }
        else
        {
            $cli1->close();
            $cli2->close();
            $response->end("OK\n");
        }
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
