--TEST--
swoole_http_client_coro: add array data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $uri = 'http://' . HTTPBIN_SERVER_HOST . ':' . HTTPBIN_SERVER_PORT . '/post';
    $data = [];
    for ($n = MAX_REQUESTS; $n--;) {
        $data[get_safe_random()] = get_safe_random();
    }
    $body = httpGetBody($uri, ['method' => 'POST', 'data' => $data]);
    $form = json_decode($body, true)['form'];
    Assert::eq($form, $data);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
