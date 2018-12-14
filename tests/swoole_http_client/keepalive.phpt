--TEST--
swoole_http_client: keepalive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    echo file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/keep");
    echo file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/notkeep");
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null'
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
    $http->on('request', function ($request, swoole_http_response $response) use ($http, $pm)
    {
        $route = $request->server['request_uri'];
        if ($route == '/info')
        {
            $response->end($request->header['connection']);
            return;
        }
        elseif ($route == '/keep')
        {
            $cli = new swoole_http_client('127.0.0.1', $pm->getFreePort());
            $cli->set(array(
                'keep_alive' => 1,
            ));
            $cli->setHeaders(array('User-Agent' => "swoole"));
            $cli->on('close', function ($cli) use ($response)
            {
            });
            $cli->on('error', function ($cli) use ($response)
            {
                echo "error";
                $response->end("error");
            });
            $cli->get('/info', function ($cli) use ($response)
            {
                $response->end($cli->body . "\n");
                $cli->close();
            });
            $http->cli = $cli;
        }
        elseif ($route == '/notkeep')
        {
            $cli = new swoole_http_client('127.0.0.1', $pm->getFreePort());
            $cli->set(array(
                'keep_alive' => 0,
            ));
            $cli->setHeaders(array('User-Agent' => "swoole"));
            $cli->on('close', function ($cli) use ($response)
            {
            });
            $cli->on('error', function ($cli) use ($response)
            {
                echo "error";
                $response->end("error");
            });
            $cli->get('/info', function ($cli) use ($response)
            {
                $response->end($cli->body . "\n");
            });
        }
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
Done
--EXPECTREGEX--
keep-alive
closed
Done.*
