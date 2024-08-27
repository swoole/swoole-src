<?php
$http = new Swoole\Http\Server("0.0.0.0", 9501);

$http->set([
    'open_http2_protocol' => 1,
]);

/**
 * nghttp -v http://localhost:9501
 */
$http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    $n = 5;
    while ($n--) {
        $response->write("hello world, #$n <br />\n");
        Co\System::sleep(1);
    }
    $response->end("hello world");
});

$http->start();

