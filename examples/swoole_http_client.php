<?php
ini_set('display_errors',1);
//error_reporting(E_ALL);
error_reporting(0);
$http = new swoole_http_server("", 9501, SWOOLE_BASE);

$http->set([
        //'worker_num' => 2,
]);
$i = 0;
$http->on('request', function ($request, swoole_http_response $response)use(&$i) {

        $route = $request->server['request_uri'];
        if($route == '/info'){
                $response->end(json_encode($request));
                return;
        }

        $cli = new swoole_http_client('127.0.0.1', 9501);
        $cli->set([
                'timeout' => 0.3,
                'keep_alive' => 1,
        ]);
	//post request
        $cli->setData(http_build_query(['a'=>123,'b'=>"哈哈"]));
        $cli->setHeaders(['User-Agent' => "swoole"]);
        $cli->on('close', function($cli)use($response){
                //      echo "close\n";
                });
        $cli->on('error', function($cli) use ($response){
                $response->end("error");
                });
        $cli->execute('/info', function($cli)use( $response, &$i){
        	$cli->setHeaders(['User-Agent' => "swoole"]);
		//get request
                $cli->execute('/info', function($cli)use($response, &$i){
                        $ret = json_encode($cli->headers) . "\nSERVER RESPONSE: ". $cli->body;
                        $response->end($ret);
                        $cli->close();
                        });
                });


        if($i++ == 1000){
            echo "----->Mem: ", memory_get_usage(), "b\n";
            $i = 0;
        }

});

$http->start();
