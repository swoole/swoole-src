--TEST--
Test of swoole_http_client timeout
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
include "include.inc";

function start_swoole_http_server() {
	$code = <<<'DOC'
		$http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
		$http->set(array(
				'worker_num' => 2,
		));
		$http->on('request', function ($request, swoole_http_response $response) {
				$route = $request->server['request_uri'];
				if($route == '/info'){
						$response->end("111");
						return;
				}else{
					$cli = new swoole_http_client('127.0.0.1', 9502);
					$cli->finished = false;
					swoole_timer_after(500, function()use($cli, $response){
						if(!$cli->finished){
							$response->end("timeout\n");
							$cli->close();
						}
					});
					
					$cli->setHeaders(array('User-Agent' => "swoole"));
					$cli->on('close', function($cli)use($response){
						$cli->finished = true;
						echo "close";
					});
					$cli->on('error', function($cli) use ($response){
							$cli->finished = true;
							echo "error";
							$response->end("error");
					});
					$cli->post('/info', array('bat' => "man"), function($cli)use( $response){
						$cli->finished = true;
						$response->end($cli->body."\n");
					});
				}
		});

		$http->start();
DOC;
	
	swoole_php_fork($code);
}
sleep(1);	//wait the release of port 9501
start_swoole_http_server();
sleep(1);
echo file_get_contents("http://127.0.0.1:9501/");
?>
Done
--EXPECTREGEX--
timeout
Done.*
--CLEAN--
