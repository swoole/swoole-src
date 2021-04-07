--TEST--
swoole_curl/guzzle: promise
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
use GuzzleHttp\Promise;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $client = new Client(['base_uri' => 'http://httpbin.org']);

    // Initiate each request but do not block
    $promises = [
        'a' => $client->requestAsync('POST', '/post', ['json' => ['data' => 'hello test1!']]),
        'b'   => $client->requestAsync('POST', '/post', ['json' => ['data' => 'hello test2!']]),
        'b'  => $client->requestAsync('POST', '/post', ['json' => ['data' => 'hello test3!']]),
    ];

    // Wait on all of the requests to complete.
    $results = Promise\unwrap($promises);

    // You can access each result using the key provided to the unwrap
    // function.
    echo json_decode($results['a']->getBody()->getContents())->data . PHP_EOL;
    echo $results['b']->getHeaderLine('Content-Type') . PHP_EOL;
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
{"data":"hello test1!"}
application/json
Done
