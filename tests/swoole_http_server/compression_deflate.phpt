--TEST--
swoole_http_server: deflate response uses the zlib data format
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const HTTP_GET_REQUEST = "GET / HTTP/1.1\r\nAccept-Encoding: deflate\r\n\r\n";

$content = str_repeat(get_safe_random(256), 8);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $content) {
    Co\run(function () use ($pm, $content) {
        $client = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (Assert::true($client->connect('127.0.0.1', $pm->getFreePort()))) {
            if (Assert::eq($client->sendAll(HTTP_GET_REQUEST), strlen(HTTP_GET_REQUEST))) {
                $response = $client->recv();
                Assert::contains($response, 'Content-Encoding: deflate');
                $body = substr($response, strpos($response, "\r\n\r\n") + 4);
                Assert::eq(gzuncompress($body), $content);
            }
        }
        $client->close();
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $content) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'http_compression' => true,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($content) {
        $response->end($content);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
