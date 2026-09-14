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

register_shutdown_function(function (){
   phpt_show_usage();
});

const N = 4;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
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

        go(function () use ($pm, $barrier, &$result) {
            $client = new Client([
                'base_uri' => "https://127.0.0.1:{$pm->getFreePort()}/",
                'verify' => false,
            ]);
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
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function ($request, $response) {
        $response->end(base64_decode(substr($request->server['request_uri'], 8)));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
