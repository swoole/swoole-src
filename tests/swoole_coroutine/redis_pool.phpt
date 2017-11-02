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
    echo curlGet("http://127.0.0.1:9501/");
    echo curlGet("http://127.0.0.1:9501/");
    echo curlGet("http://127.0.0.1:9501/");
    swoole_process::kill($pid);
};

$count = 0;
$pool = new SplQueue();

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
        global $count, $pool;
        if (count($pool) == 0)
        {
            $redis = new Swoole\Coroutine\Redis();
            $redis->id = $count;
            $res = $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
            if ($res == false)
            {
                fail:
                $response->end("ERROR\n");
                return;
            }
            $count++;
            $pool->push($redis);
        }

        $redis = $pool->pop();
        $ret = $redis->set('key', 'value');
        if ($ret)
        {
            $response->end("OK[$count]\n");
        }
        else
        {
            goto fail;
        }
        $pool->push($redis);

    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK[1]
OK[1]
OK[1]
