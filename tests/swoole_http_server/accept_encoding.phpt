--TEST--
swoole_http_server: accept encoding type
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Runtime;
use function Swoole\Coroutine\run;

function curl_request(string $type, string $url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Accept-Encoding: {$type}"]);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $headerLine) use ($type) {
        if (stripos($headerLine, 'Content-Encoding:') !== false) {
            Assert::true(stripos($headerLine, $type) !== false);
        }
        return strlen($headerLine);
    });
    curl_exec($ch);
    curl_close($ch);
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm)
{
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($pm) {
        $url = "http://127.0.0.1:".$pm->getFreePort();
        curl_request('br', $url);
        curl_request('gzip', $url);
        curl_request('deflate', $url);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->set([
        'http_compression' => true,
    ]);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function (Request $request, Response $response) {
        $response->end(co::readFile(__DIR__ . '/../../README.md'));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--