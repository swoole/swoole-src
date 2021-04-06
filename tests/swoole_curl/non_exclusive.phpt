--TEST--
swoole_curl: non-exclusive
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
        $url = "http://127.0.0.1:".$pm->getFreePort()."/?code=".urlencode($code);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);

        $header_count = 0;
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) use (&$header_count) {
            Assert::eq(curl_getinfo($ch, CURLINFO_HTTP_CODE), 200);
            $header_count++;
            return strlen($strHeader);
        });

        $output = curl_exec($ch);
        Assert::eq($output, "Hello World\n".$code);
        if ($output === false) {
            echo "CURL Error:" . curl_error($ch);
        }
        Assert::greaterThan($header_count, 1);
        curl_close($ch);
        echo "Close\n";
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
        usleep(30000);
        $response->end("Hello World\n".$request->get['code']);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
Close
Done
