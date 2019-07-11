--TEST--
swoole_redis_coro: redis client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        $pm->kill();
    });
};

$count = 0;
$pool = new SplQueue();

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
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
            $pool->enqueue($redis);
        }

        $redis = $pool->dequeue();
        $ret = $redis->set('key', 'value');
        if ($ret)
        {
            $response->end("OK[$count]\n");
        }
        else
        {
            goto fail;
        }
        $pool->enqueue($redis);

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
