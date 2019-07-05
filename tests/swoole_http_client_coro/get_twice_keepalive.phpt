--TEST--
swoole_http_client_coro: get twice and keepalive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
const N = 2;

Swoole\Coroutine\Run(function () {
    $client = new Client('www.zhe800.com', 443, true);
    for ($i = 0; $i < N; $i++) {
        $rand = mt_rand(100000, 999999999);
        $path = "/email_subscribe?email=" . $rand . "@" . substr(md5(microtime(true)), 0, 8) . ".com";
        Assert::assert($client->get($path));
        Assert::assert($client->getStatusCode() == 200);
    }
});

?>
--EXPECT--
