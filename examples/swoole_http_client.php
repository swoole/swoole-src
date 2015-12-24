<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
$http = new swoole_http_server("", 9501, SWOOLE_BASE);

$http->set([
        'worker_num' => 2,
]);

$http->on('request', function ($request, swoole_http_response $response) {

        $route = $request->server['request_uri'];
        if($route == '/info'){
        $response->end(111);
        return;
        }

        $cli = new swoole_http_client('127.0.0.1', 9501);
        $cli->set([
                'timeout' => 0.3,
                'keep_alive' => 1,
        ]);
        $cli->on('close', function($cli)use($response){
                //      echo "close\n";
                });
        $cli->on('error', function($cli) use ($response){
                echo "error\n";
                $response->end("error");
                });
        $cli->execute('/info', function($cli)use( $response){
                $cli->execute('/info', function($cli)use($response){
                        $ret = json_encode($cli->headers) . $cli->body;
                        $response->end($ret);
                        $cli->close();
                        //echo "----->Mem: ", memory_get_usage(), "b\n";
                        });
                });
});

$http->start();

