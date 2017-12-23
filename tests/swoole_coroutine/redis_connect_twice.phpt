--TEST--
swoole_coroutine: redis client
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
        $redis = new Swoole\Coroutine\Redis();
        $res = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
        $res2 = @$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
        assert($res2 == false);
        if (!$res)
        {
            fail:
            $response->end("ERROR\n");
            return;
        }
        $ret = $redis->set('key', 'value');
        if (!$ret) {
            goto fail;
        }
        $ret = $redis->get('key');
        if (!$ret) {
            goto fail;
        }
        assert($ret == "value");
        if (strlen($ret) > 0) {
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
