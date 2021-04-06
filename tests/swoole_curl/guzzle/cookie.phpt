--TEST--
swoole_curl/guzzle: cookie
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
use GuzzleHttp\Cookie\CookieJar;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $client = new Client();
    $jar = CookieJar::fromArray(
        [
            'some_cookie' => 'foo',
            'other_cookie' => 'barbaz1234'
        ],
        'httpbin.org'
    );
    $r = $client->request('GET', 'http://httpbin.org/cookies', [
        'cookies' => $jar
    ]);
    Assert::eq($r->getStatusCode(), 200);
    Assert::eq(json_decode($r->getBody()->getContents(), true)['cookies']['some_cookie'], 'foo');
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
Done
