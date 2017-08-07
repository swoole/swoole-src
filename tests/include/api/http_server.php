<?php
$http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
$http->set(array(
    'log_file' => '/dev/null',
    "http_parse_post" => 1,
    "upload_tmp_dir" => "/tmp",
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
        $response->end($request->header['user-agent']);
        return;
    }
    elseif ($route == '/cookies')
    {
        $response->end(@json_encode($request->cookie));
        return;
    }
    elseif ($route == '/get')
    {
        $response->end(@json_encode($request->get));
        return;
    }
    elseif ($route == '/post')
    {
        $response->end(@json_encode($request->post));
        return;
    }
    elseif ($route == '/get_file')
    {
        $response->sendfile(TEST_IMAGE);
        return;
    }
    elseif ($route == '/upload_file')
    {
        $response->end(json_encode([
            'files' => $request->files,
            'md5' => md5_file($request->files['test_jpg']['tmp_name']),
            'post' => $request->post
        ]));
        return;
    }
    elseif ($route == '/gzip')
    {
        $response->gzip(5);
        Swoole\Async::readFile(__DIR__ . '/../../../README.md', function ($file, $content) use ($response) {
            $response->end($content);
        });
        return;
    }
    else
    {
        $cli = new swoole_http_client('127.0.0.1', 9501);
        $cli->set(array(
            'timeout' => 0.3,
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
    }
});
$http->start();