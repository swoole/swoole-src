<?php
function dump($var)
{
    return highlight_string("<?php\n\$array = ".var_export($var, true).";", true);
}
$key_dir = dirname(dirname(__DIR__)) . '/tests/ssl';
//$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE);
$http = new swoole_http_server("0.0.0.0", 9501);
//$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
//https
//$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
//$http->setGlobal(HTTP_GLOBAL_ALL, HTTP_GLOBAL_GET|HTTP_GLOBAL_POST|HTTP_GLOBAL_COOKIE);
$http->set([
//    'daemonize' => 1,
//    'open_cpu_affinity' => 1,
//    'task_worker_num' => 1,
    //'open_cpu_affinity' => 1,
    //'task_worker_num' => 100,
    //'enable_port_reuse' => true,
//    'worker_num' => 4,
    //'log_file' => __DIR__.'/swoole.log',
//    'reactor_num' => 24,
    //'dispatch_mode' => 3,
    //'discard_timeout_request' => true,
//    'open_tcp_nodelay' => true,
//    'open_mqtt_protocol' => true,
    //'task_worker_num' => 1,
    //'user' => 'www-data',
    //'group' => 'www-data',
//'daemonize' => true,
//    'ssl_cert_file' => $key_dir.'/ssl.crt',
//    'ssl_key_file' => $key_dir.'/ssl.key',
]);

$http->listen('127.0.0.1', 9502, SWOOLE_SOCK_TCP);

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
    /**
     * Cookie Test
     */
    //$response->cookie('test1', '1234', time() + 86400, '/');
//    $response->cookie('test2', '5678', time() + 86400);
//    var_dump($response->cookie);
//    var_dump($request->cookie);
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
    //var_dump($request->server['request_uri'], substr($request->server['request_uri'], -4, 4));

    if (substr($request->server['request_uri'], -8, 8) == 'test.jpg')
    {
        $response->header('Content-Type', 'image/jpeg');
        $response->sendfile(dirname(__DIR__).'/test.jpg');
        return;
    }
    if ($request->server['request_uri'] == '/test.txt')
    {
        $last_modified_time = filemtime(__DIR__ . '/test.txt');
        $etag = md5_file(__DIR__ . '/test.txt');
        // always send headers
        $response->header("Last-Modified", gmdate("D, d M Y H:i:s", $last_modified_time) . " GMT");
        $response->header("Etag", $etag);
        if (strtotime($request->header['if-modified-since']) == $last_modified_time or trim($request->header['if-none-match']) == $etag)
        {
            $response->status(304);
            $response->end();
        }
        else
        {
            $response->sendfile(__DIR__ . '/test.txt');
        }
        return;
    }
    if ($request->server['request_uri'] == '/favicon.ico')
    {
        $response->status(404);
        $response->end();
        return;
    }
//    else
//    {
        //var_dump($request->post);
    //var_export($request->cookie);
//    var_dump($request->rawContent());
//    if ($request->server['request_method'] == 'POST')
//    {
//        var_dump($request->post);
//    }
//    echo "GET:" . var_export($_GET, true)."\n";
//    echo "POST:" . var_export($_POST, true)."\n";
//    echo "get:" . var_export($request->get, true)."\n";
//    echo "post:" . var_export($request->post, true)."\n";
    //var_dump($request->server);
    $output = '';
    $output .= "<h2>HEADER:</h2>".dump($request->header);
    $output .= "<h2>SERVER:</h2>".dump($request->server);
    if (!empty($request->files))
    {
        $output .= "<h2>FILE:</h2>".dump($request->files);
    }
    if (!empty($request->cookie))
    {
        $output .= "<h2>COOKIES:</h2>".dump($request->cookie);
    }
    if (!empty($request->get))
    {
        $output .= "<h2>GET:</h2>".dump($request->get);
    }
    if (!empty($request->post))
    {
        $output .= "<h2>POST:</h2>".dump($request->post);
    }
    //$response->header('X-Server', 'Swoole');
    //unset($request, $response);
//    swoole_timer_after(2000, function() use ( $response) {
        $response->end("<h1>Hello Swoole.</h1>".$output);
//    });
//    }
    return;
    //var_dump($request);
//    var_dump($_GET);
    //var_dump($_POST);
    //var_dump($_COOKIE);
    //$response->status(301);
    //$response->header("Location", "http://www.baidu.com/");
    //$response->cookie("hello", "world", time() + 3600);
//    $response->header("Content-Type", "text/html; charset=utf-8");

    //var_dump($request->post);
//    var_dump($request->get);

//    echo strlen(gzdeflate("<h1>Hello Swoole.</h1>"));
//    $response->end("<h1>Hello Swoole.</h1>");
    //$response->end("<h1>Hello Swoole. #".str_repeat('A', rand(100, 999))."</h1>");
    //global $http;
    //$http->task("hello world");
    $file = realpath(__DIR__ . '/../' . $request->server['request_uri']);
    if (is_file($file))
    {
        echo "http get file=$file\n";
        if (substr($file, -4) == '.php')
        {
            $response->gzip();
        }
        else
        {
            $response->header('Content-Type', 'image/jpeg');
        }
        $content = file_get_contents($file);
        echo "response size = " . strlen($content) . "\n";

//        $response->write($content);
//        $response->end();

        $response->end($content);
    }
    else
    {
        $response->end("<h1>Hello Swoole.</h1>");
    }
}

$http->on('request', 'no_chunk');

$http->on('finish', function ()
{
    echo "task finish";
});

$http->on('task', function ()
{
    echo "async task\n";
});

//$http->on('close', function(){
//    echo "on close\n";
//});


$http->on('workerStart', function ($serv, $id)
{
    //var_dump($serv);
});

$http->start();
