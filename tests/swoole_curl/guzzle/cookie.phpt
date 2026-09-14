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

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use SwooleTest\CurlManager;

$cm = new CurlManager;
$cm->run(function ($host) {
    $client = new Client();
    $jar = CookieJar::fromArray(
        [
            'some_cookie' => 'foo',
            'other_cookie' => 'barbaz1234'
        ],
        '127.0.0.1'
    );
    $r = $client->request('GET', "http://{$host}/get.php?test=cookie_get", [
        'cookies' => $jar
    ]);
    Assert::eq($r->getStatusCode(), 200);
    Assert::eq(json_decode($r->getBody()->getContents(), true)['some_cookie'], 'foo');
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
Done
