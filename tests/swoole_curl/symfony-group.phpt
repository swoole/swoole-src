--TEST--
swoole_curl: symfony http client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Runtime;
use Symfony\Component\HttpClient\ScopingHttpClient as SymfonyScopingHttpClient;
use Symfony\Component\HttpClient\HttpClient as SymfonyHttpClient;

use Swoole\Coroutine\WaitGroup;
use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $httpClient = SymfonyScopingHttpClient::forBaseUri(SymfonyHttpClient::create(), 'http://httpbin.org', [
        'max_duration' => 5,
        'headers' => [
            'Accept' => 'application/json',
        ],
    ]);

    $wg = new WaitGroup();
    $results = [];
    $args = ['1', '2', '3'];

    foreach ($args as $arg) {
        go(function () use ($wg, $httpClient, $delay, &$results) {
            $wg->add();
            $results[] = $httpClient->request('GET', '/get?key='.$arg)->toArray();
            $wg->done();
        });
    }

    $wg->wait(5);

    Assert::count($results, \count($args));
    foreach ($results as $result) {
        Assert::notEmpty($result);
        Assert::oneOf($result['args']['key'], $args);
    }

    echo 'Done' . PHP_EOL;
});

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
?>
--EXPECT--
Done
