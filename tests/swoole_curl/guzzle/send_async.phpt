--TEST--
swoole_curl/guzzle: send async
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $client = new Client();
    $response = $client->request('GET', 'https://httpbin.org');

    echo $response->getStatusCode(), PHP_EOL; // 200
    echo $response->getHeaderLine('content-type'), PHP_EOL;

    // Send an asynchronous request.
    $request = new Request('GET', 'http://httpbin.org');
    $promise = $client->sendAsync($request)->then(function ($response) {
        echo 'I completed! ' . $response->getStatusCode() . PHP_EOL;
    });

    $promise->wait();
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
200
text/html; charset=utf-8
I completed! 200
Done
