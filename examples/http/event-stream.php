<?php
$http = new Swoole\Http\Server("0.0.0.0", 9501);

$http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
    if ($req->server['request_uri'] == '/stream') {
        $resp->header("Content-Type", "text/event-stream");
        $resp->header("Cache-Control", "no-cache");
        $resp->header("Connection", "keep-alive");
        $resp->header("X-Accel-Buffering", "no");
        $resp->header('Content-Encoding', '');
        $resp->header("Content-Length", '');
        $resp->end();
        go(function () use ($resp, $http) {
            while (true) {
                Co::sleep(1);
                $http->send($resp->fd, 'data: ' . base64_encode(random_bytes(random_int(16, 128))). "\n\n");
            }
        });
    } elseif ($req->server['request_uri'] == '/') {
        $resp->end(<<<HTML
<html>
<script>
const source = new EventSource("/stream");
source.onmessage = function(e){
    console.log(e);
};
source.onerror = function(e){
    console.log(e);
};
</script>
</html>
HTML
        );
    } else {
        $resp->status(404);
        $resp->end();
    }
});

$http->start();
