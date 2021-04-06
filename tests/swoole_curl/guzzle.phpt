--TEST--
swoole_curl: guzzle
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

use Swoole\Coroutine\Barrier;
use Swoole\Runtime;
use GuzzleHttp\Client;
use GuzzleHttp\Promise;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

const N = 4;

run(function () {
    $barrier = Barrier::make();
    $result = [];
    go(function () use ($barrier, &$result) {
        $client = new Client();
        $promises = [
            'baidu' => $client->getAsync('http://www.baidu.com/'),
            'qq' => $client->getAsync('https://www.qq.com/'),
            'gov' => $client->getAsync('http://www.gov.cn/')
        ];
        $responses = Promise\Utils::unwrap($promises);
        Assert::contains($responses['baidu']->getBody(), '百度');
        Assert::contains(iconv('gbk', 'utf-8', $responses['qq']->getBody()), '腾讯');
        Assert::contains($responses['gov']->getBody(), '中华人民共和国');
        $result['task_1'] = 'OK';
    });

    go(function () use ($barrier, &$result) {
        $client = new Client(['base_uri' => 'http://httpbin.org/']);
        $n = N;
        $data = $promises = [];
        while ($n--) {
            $key = 'req_' . $n;
            $data[$key] = uniqid('swoole_test');
            $promises[$key] = $client->getAsync('/base64/' . base64_encode($data[$key]));
        }
        $responses = Promise\Utils::unwrap($promises);

        $n = N;
        while ($n--) {
            $key = 'req_' . $n;
            Assert::eq($responses[$key]->getBody(), $data[$key]);
        }
        $result['task_2'] = 'OK';
    });

    Barrier::wait($barrier);
    Assert::eq($result['task_1'], 'OK');
    Assert::eq($result['task_2'], 'OK');
    echo 'Done' . PHP_EOL;
});
?>
--EXPECT--
Done
