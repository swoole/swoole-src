--TEST--
swoole_http_client: get
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

function start_swoole_http_server() {
	$func = function ()
    {
        $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
        $http->set(array(
            'worker_num' => 2,
            'log_file' => '/dev/null'
        ));
        $http->on('request', function ($request, swoole_http_response $response)
        {
            $route = $request->server['request_uri'];
            if ($route == '/info')
            {
                $response->end($request->header['user-agent']);
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
                });
            }
        });
        $http->start();
    };
	swoole_php_fork($func);
}
sleep(1);	//wait the release of port 9501
start_swoole_http_server();
sleep(1);
echo file_get_contents("http://127.0.0.1:9501/");
?>
Done
--EXPECTREGEX--
swoole
Done.*
--CLEAN--
