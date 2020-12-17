--TEST--
swoole_server: sleep
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Http\Request;
use Swoole\Http\Response;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;

const N = 8;

$pm->parentFunc = function () use ($pm) {
    $s = microtime(true);
    Co::set([Constant::OPTION_HOOK_FLAGS => SWOOLE_HOOK_ALL]);
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
    $http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        Constant::OPTION_ENABLE_COROUTINE => true,
        Constant::OPTION_HOOK_FLAGS => SWOOLE_HOOK_ALL,
    ]);

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
