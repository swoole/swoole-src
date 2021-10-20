--TEST--
swoole_curl: select timeout
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Coroutine\System;
use Swoole\Http\Request;
use Swoole\Http\Response;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const TIMEOUT = 0.5;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
        $mh = curl_multi_init();

        $add_handle = function ($url) use($mh) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_multi_add_handle($mh, $ch);
            return $ch;
        };

        $ch1 = $add_handle("http://127.0.0.1:{$pm->getFreePort()}/");

        $active = null;

        do {
            $mrc = curl_multi_exec($mh, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);

        $now = microtime(true);

        while ($active && $mrc == CURLM_OK) {
            $tm = microtime(true);
            $n = curl_multi_select($mh, TIMEOUT);
            Assert::lessThan(microtime(true) - $tm, TIMEOUT + 0.01);

            $error = swoole_last_error();
            phpt_var_dump('select return value: '.$n);
            phpt_var_dump('swoole error: '.$error);
            if ($n != -1) {
                do {
                    $mrc = curl_multi_exec($mh, $active);
                    phpt_var_dump('exec return value: '.$mrc);
                } while ($mrc == CURLM_CALL_MULTI_PERFORM);
            }
            if (microtime(true) - $now >= TIMEOUT * 4) {
                echo "TIMEOUT\n";
                break;
            }
        }

        Assert::eq(curl_multi_info_read($mh), false);
        curl_multi_remove_handle($mh, $ch1);
        curl_multi_close($mh);
    });
    $pm->kill();
    echo "Done\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort());
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null', 'max_wait_time' => 1,]);
    $http->on("start", function ($server) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (Request $request, Response $response) {
        sleep(20000);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
TIMEOUT
Done
