--TEST--
swoole_http_client: timeout
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    echo file_get_contents("http://127.0.0.1:9501/");
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
    $http->set(array(
        'worker_num' => 2,
        'task_worker_num' => 2,
        'log_file' => '/dev/null',
    ));
    $http->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        if ($pm)
        {
            $pm->wakeup();
        }
    });
    $http->on('request', function ($request, swoole_http_response $response)
    {
        $route = $request->server['request_uri'];
        if ($route == '/info')
        {
            $response->end("111");
            return;
        }
        else
        {
            $cli = new swoole_http_client('192.0.0.1', 9502);
            $cli->setHeaders(array('User-Agent' => "swoole"));
            $cli->on('close', function ($cli) use ($response)
            {
                echo "close\n";
            });
            $cli->on('error', function ($cli) use ($response)
            {
                echo "error\n";
                $response->end("error\n");
            });
            $cli->post('/info', array('bat' => "man"), function ($cli) use ($response)
            {
                if ($cli->statusCode == 200)
                {
                    $response->end($cli->body . "\n");
                }
                $cli->close();
            });
        }
    });

    $http->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {

    });

    $http->on('finish', function (swoole_server $serv, $fd, $rid, $data)
    {

    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
Done
--EXPECTREGEX--
error
error
Done.*
--CLEAN--
