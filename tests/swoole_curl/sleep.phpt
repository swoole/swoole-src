--TEST--
swoole_curl: sleep
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Runtime;

use function Swoole\Coroutine\run;
$pm = new SwooleTest\ProcessManager;

const N = 8;

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    $s = microtime(true);
    run(function () use ($pm) {
        $n = N;
        while($n--) {
            go(function() use ($pm) {
                $ch = curl_init();
                $code = uniqid('swoole_');
                $url = "http://127.0.0.1:".$pm->getFreePort()."/?code=".urlencode($code);

                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_HEADER, 0);
                curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
                    return strlen($strHeader);
                });

                $output = curl_exec($ch);
                Assert::eq($output, "Hello World\n".$code);
                if ($output === false) {
                    echo "CURL Error:" . curl_error($ch);
                }
                curl_close($ch);
            });
        }
    });
    Assert::lessThan(microtime(true) - $s, 0.5);
    $pm->kill();
    echo "Done\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort());
    $http->set(['worker_num' => N, 'log_file' => '/dev/null']);

    $http->on("start", function ($server) use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (Request $request, Response $response) {
        usleep(300000);
        $response->end("Hello World\n".$request->get['code']);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Done
