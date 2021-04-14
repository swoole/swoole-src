--TEST--
swoole_curl/guzzle: cannot_cancel_finished
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\Promise;
use GuzzleHttp\Psr7\Request;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $handler = new CurlMultiHandler();
    $response = $handler(new Request('GET', 'http://httpbin.org/get'), []);
    $response->wait();
    $response->cancel();
    Assert::true(Promise\Is::fulfilled($response));
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
Done
