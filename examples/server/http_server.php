<?php
$key_dir = dirname(dirname(__DIR__)).'/tests/ssl';
$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE);
//$http = new swoole_http_server("0.0.0.0", 9501);
//https
//$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
//$http->setGlobal(HTTP_GLOBAL_ALL, HTTP_GLOBAL_GET|HTTP_GLOBAL_POST|HTTP_GLOBAL_COOKIE);
$http->set([
//    'worker_num' => 4,
//    'open_tcp_nodelay' => true,
    //'task_worker_num' => 0,
    //'user' => 'www-data',
    //'group' => 'www-data'
    //'ssl_cert_file' => $key_dir.'/ssl.crt',
    //'ssl_key_file' => $key_dir.'/ssl.key',
]);

function chunk(swoole_http_request $request, swoole_http_response $response)
{
    $response->write("<h1>hello world1</h1>");
    //sleep(1);
    $response->write("<h1>hello world2</h1>");
    //sleep(1);
    $response->end();
}

function no_chunk(swoole_http_request $request, swoole_http_response $response)
{

//	try
//	{
//		if (rand(1, 99) % 2 == 1)
//		{
//			throw new Exception("just for fun.");
//		}
//		$response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
//	}
//	catch(Exception $e)
//	{
//		$response->end("<h1>Exceptiom</h1><div>".$e->getMessage()."</div>");
//	}

    //var_dump($request->server);
    //var_dump($request->header);
    //var_dump($request);
//    var_dump($_GET);
    //var_dump($_POST);
    //var_dump($_COOKIE);
    //$response->status(301);
    //$response->header("Location", "http://www.baidu.com/");
    //$response->cookie("hello", "world", time() + 3600);
    $response->header("Content-Type", "text/html; charset=utf-8");
    //var_dump($request->rawContent());
    //var_dump($request->post);
//    var_dump($request->get);
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
    //global $http;
    //$http->task("hello world");
}
$http->on('request', 'chunk');

$http->on('finish', function(){
    echo "task finish";
});

$http->on('task', function(){
    echo "async task\n";
});
//
//$http->on('close', function(){
//    echo "on close\n";
//});

$http->start();
