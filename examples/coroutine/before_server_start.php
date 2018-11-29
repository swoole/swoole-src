<?php
go(function ()
{
    co::sleep(1);

    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);

    $http->on("start", function ($server)
    {
        echo "Swoole http server is started at http://127.0.0.1:9501\n";
    });

    $http->on("request", function ($request, $response)
    {
        var_dump($request->header);
        var_dump($request->server);

        $response->header("Content-Type", "text/plain");
        $response->status(200);
        $response->end("test");
    });
    echo "start\n";
    $http->start();
    echo "end\n";
});
