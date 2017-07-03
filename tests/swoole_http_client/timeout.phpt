--TEST--
swoole_http_client: timeout
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

function start_swoole_http_server() {
	swoole_php_fork(function(){
        $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
        $http->set(array(
            'worker_num' => 2,
            'log_file' => '/dev/null',
        ));
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
                    if ($cli->statusCode == 200) {
                        $response->end($cli->body . "\n");
                    }
                });
            }
        });

        $http->start();
    });
}
sleep(1);	//wait the release of port 9501
start_swoole_http_server();
sleep(1);
echo file_get_contents("http://127.0.0.1:9501/");
?>
Done
--EXPECTREGEX--
error
error
Done.*
--CLEAN--
