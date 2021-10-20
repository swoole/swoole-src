--TEST--
swoole_curl: select twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;
use Swoole\Coroutine;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Coroutine\System;
use Swoole\Http\Request;
use Swoole\Http\Response;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const TIMEOUT = 1.5;

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

        $cid = Coroutine::getCid();
        go(function () use($cid) {
            System::sleep(0.005);
            Coroutine::cancel($cid);
        });

        while ($active && $mrc == CURLM_OK) {
            $n = curl_multi_select($mh, TIMEOUT);
            phpt_var_dump('return value：'.$n);
            phpt_var_dump('swoole error：'.swoole_last_error());
            if ($n != -1) {
                do {
                    $mrc = curl_multi_exec($mh, $active);
                } while ($mrc == CURLM_CALL_MULTI_PERFORM);
            }
            if (Coroutine::isCanceled()) {
                Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
                echo "CANCELED\n";
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
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
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
CANCELED
Done
