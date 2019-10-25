<?php
Co::set([
    'trace_flags' => SWOOLE_TRACE_HTTP2,
    'log_level' => 0,
]);
go(function () {
	$server = new Co\Http\Server("127.0.0.1", 9501, false);
	/**
	 * 静态文件处理器
	 */
	//$server->handle('/static', $server->getStaticHandler());
	/**
	 * WebSocket应用
	 */
	$server->handle('/websocket', function ($request, $ws) {
		$ws->upgrade();

        $frame1 = $ws->recv();
        $frame2 = $ws->recv();
		var_dump($frame1, $frame2);

		$ws->push("hello world\n");

		while(true) {
			echo "recv begin:\n";
			$frame = $ws->recv();
			if ($frame == false) {
			    echo "ws client is closed\n";
                var_dump("Error: ", swoole_last_error());
			    break;
            }
			echo $frame->data ."\n";
			$ws->push("hello world");
		}
	});
	/**
	 * Http应用
	 */
	$server->handle('/', function ($request, $response) {
	    var_dump($request);
		var_dump($request->get);
		$response->end("<h1>hello world</h1>");
	});

	$server->handle('/test', function ($request, $response) {
		var_dump($request->get);
		$response->end("<h1>Test</h1>");
	});

	$server->start();
});

swoole_event_wait();
