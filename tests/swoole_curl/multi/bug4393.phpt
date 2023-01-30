--TEST--
swoole_curl/multi: guzzle
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
    $guzzle = new Client();

    $test = function () use ($guzzle) {
        if (IS_IN_CI) {
            $promises = [
                'qq' => $guzzle->getAsync('https://www.qq.com/'),
                'baidu' => $guzzle->getAsync('http://www.baidu.com/'),
            ];
        } else {
            $promises = [
                'httpbin' => $guzzle->getAsync('https://www.httpbin.org/'),
                'nghttp2' => $guzzle->getAsync('https://nghttp2.org/'),
            ];
        }

        $responses = [];
        foreach (Promise\Utils::settle($promises)->wait() as $k => $v) {
            $responses[$k] = $v['value'];
        }

        if (IS_IN_CI) {
            Assert::contains($responses['baidu']->getBody(), '百度');
            Assert::contains(iconv('gbk', 'utf-8', $responses['qq']->getBody()), '腾讯');
        } else {
            Assert::contains($responses['httpbin']->getBody(), 'httpbin');
            Assert::contains($responses['nghttp2']->getBody(), 'nghttp2');
        }
    };

    $n = 2;
    while ($n--) {
        $s = microtime(true);
        $test();
        Assert::lessThan(microtime(true) - $s, 2.0);
    }

    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
Done
