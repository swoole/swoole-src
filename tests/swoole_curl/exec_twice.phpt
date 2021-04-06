--TEST--
swoole_curl: exec twice
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
        $ch = curl_init();
        $code = uniqid('swoole_');
        $url = "http://127.0.0.1:".$pm->getFreePort()."/?code=".urlencode($code);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
            return strlen($strHeader);
        });

        go(function() use ($ch) {
            Co::sleep(0.1);
            echo "co 2 exec\n";
            var_dump(curl_exec($ch), curl_errno($ch));
        });

        echo "co 1 exec\n";
        $output = curl_exec($ch);
        Assert::eq($output, "Hello World\n".$code);
        if ($output === false) {
            echo "CURL Error:" . curl_error($ch);
        }
        curl_close($ch);
        echo "close [2]\n";
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
--EXPECTF--
co 1 exec
co 2 exec

Fatal error: Uncaught Swoole\Error: cURL is executing, cannot be operated in %s:%d
Stack trace:
#0 %s(%d): curl_exec(%s)
#1 {main}
  thrown in %s on line %d
