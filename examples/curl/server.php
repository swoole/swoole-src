<?php
$http = new Swoole\Http\Server("127.0.0.1", 9801);

$http->set(['worker_num' => 8, ]);

$http->on("start", function ($server) {
    echo "Swoole http server is started at http://127.0.0.1:9501\n";
});

$http->on("request", function ($request, $response) {
    sleep(1);
    $response->end("Hello World\n");
});

$http->start();
