--TEST--
swoole_curl: keepalive
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

$pm->parentFunc = function () use ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
        $ch = curl_init();
        $code = uniqid('swoole_');

        $execFn = function () use ($ch, $code, $pm) {
            $url = "http://127.0.0.1:" . $pm->getFreePort() . "/?code=" . urlencode($code);
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
                return strlen($strHeader);
            });
            $output = curl_exec($ch);
            $info = curl_getinfo($ch);
            Assert::eq($output, "Hello World\n" . $code);
            if ($output === false) {
                exit("CURL Error:" . curl_error($ch));
            }
            return $info;
        };

        echo "co 1 exec\n";
        $info1 = $execFn();

        Co::sleep(0.1);

        echo "co 2 exec\n";
        $info2 = $execFn();

        Assert::eq($info1['local_port'], $info2['local_port']);

        curl_close($ch);
    });
    $pm->kill();
    echo "Done\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set(['worker_num' => 2, 'log_file' => '/dev/null']);

    $http->on("start", function ($server) use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function (Request $request, Response $response) {
        $response->end("Hello World\n" . $request->get['code']);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
co 1 exec
co 2 exec
Done
