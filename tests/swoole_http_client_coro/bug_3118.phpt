--TEST--
swoole_http_client_coro: Github #3118
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;

Coroutine\run(function () {
    $client = new Coroutine\Http\Client(HTTPBIN_SERVER_HOST, HTTPBIN_SERVER_PORT);
    $client->set(['timeout' => 10]);
    $codes = [200, 201, 304, 301, 302, 303,];
    foreach ($codes as $code) {
        $client->get("/status/{$code}");
        Assert::same($client->getStatusCode(), $code);
    }
});

echo "DONE\n"

?>
--EXPECT--
DONE
