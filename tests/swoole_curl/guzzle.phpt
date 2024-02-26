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

register_shutdown_function(function (){
   phpt_show_usage();
});

const N = 4;

run(function () {
    $barrier = Barrier::make();
    $result = [];
    go(function () use ($barrier, &$result) {
        $client = new Client();
        $promises = [
            'baidu' => $client->getAsync('http://www.baidu.com/'),
            'qq' => $client->getAsync('https://www.qq.com/'),
            'zhihu' => $client->getAsync('http://www.zhihu.com/')
        ];
        $responses = Promise\Utils::unwrap($promises);
        Assert::contains($responses['baidu']->getBody(), '百度');
        Assert::contains($responses['qq']->getBody(), '腾讯');
        Assert::contains($responses['zhihu']->getBody(), '知乎');
        $result['task_1'] = 'OK';
    });

    go(function () use ($barrier, &$result) {
        $client = new Client(['base_uri' => 'https://httpbin.org/']);
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
