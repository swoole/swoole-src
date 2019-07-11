--TEST--
swoole_http_server_coro: post array data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();

go(function () use ($port) {
    $server = new Co\Http\Server("127.0.0.1", $port, false);
    $server->handle('/post', function ($request, $response) {
        $response->end(json_encode(['form' => $request->post]));
    });
    $server->handle('/stop', function ($request, $response) use ($server) {
        $response->end("<h1>Stop</h1>");
        $server->shutdown();
    });
    $server->start();
});

go(function () use ($port) {
    $uri = 'http://127.0.0.1:' . $port;
    $data = [];
    for ($n = MAX_REQUESTS; $n--;) {
        $data[get_safe_random()] = get_safe_random();
    }
    $body = httpGetBody($uri . '/post', ['method' => 'POST', 'data' => $data]);
    $form = json_decode($body, true)['form'];
    Assert::same($form, $data);

    echo httpGetBody($uri . "/stop?hello=1") . PHP_EOL;
});

Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
<h1>Stop</h1>
DONE
