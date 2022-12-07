--TEST--
swoole_http_server: range
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    foreach ([false, true] as $http2) {
        Swoole\Coroutine\run(function () use ($pm, $http2) {
            $data2 = file_get_contents(TEST_IMAGE);

            // range
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15']]);
            Assert::same($response['statusCode'], 206);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, 0, 16)));
            Assert::same('bytes 0-15/218787', $response['headers']['content-range']);
            $lastModified = $response['headers']['last-modified'] ?? null;
            Assert::notNull($lastModified);
            Assert::null($response['headers']['accept-ranges'] ?? null);
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=16-31']]);
            Assert::same($response['statusCode'], 206);
            Assert::same('bytes 16-31/218787', $response['headers']['content-range']);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, 16, 16)));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=-16']]);
            Assert::same($response['statusCode'], 206);
            Assert::same('bytes 218771-218786/218787', $response['headers']['content-range']);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, -16)));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=128-']]);
            Assert::same($response['statusCode'], 206);
            Assert::same('bytes 128-218786/218787', $response['headers']['content-range']);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, 128)));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-0,-1']]);
            Assert::same($response['statusCode'], 206);
            Assert::isEmpty($response['headers']['content-range'] ?? null);
            Assert::notEq(preg_match('/multipart\/byteranges; boundary=(.+)/', $response['headers']['content-type'] ?? '', $matches), false);
            $boundary = $matches[1];
            $expect = sprintf(<<<BIN
--{$boundary}
Content-Type: image/jpeg
Content-Range: bytes 0-0/218787

%s
--{$boundary}
Content-Type: image/jpeg
Content-Range: bytes 218786-218786/218787

%s
--{$boundary}--

BIN
            , substr($data2, 0, 1), substr($data2, -1));
            $expect = str_replace(PHP_EOL, "\r\n", $expect);
            Assert::same(bin2hex($expect), bin2hex($response['body']));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15,32-63']]);
            Assert::same($response['statusCode'], 206);
            Assert::notEq(preg_match('/multipart\/byteranges; boundary=(.+)/', $response['headers']['content-type'] ?? '', $matches), false);
            $boundary = $matches[1];
            $expect = sprintf(<<<BIN
--{$boundary}
Content-Type: image/jpeg
Content-Range: bytes 0-15/218787

%s
--{$boundary}
Content-Type: image/jpeg
Content-Range: bytes 32-63/218787

%s
--{$boundary}--

BIN
            , substr($data2, 0, 16), substr($data2, 32, 32));
            $expect = str_replace(PHP_EOL, "\r\n", $expect);
            Assert::same(bin2hex($expect), bin2hex($response['body']));

            // if-range
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15', 'If-Range' => $lastModified]]);
            Assert::same($response['statusCode'], 206);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, 0, 16)));

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15', 'If-Range' => 'test']]);
            Assert::same($response['statusCode'], 206);
            Assert::same(bin2hex($response['body']), bin2hex(substr($data2, 0, 16)));

            $lastModifiedTime = strtotime($lastModified);
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15', 'If-Range' => date(DATE_RFC7231, $lastModifiedTime - 1)]]);
            Assert::same($response['statusCode'], 200);
            Assert::same(bin2hex($response['body']), bin2hex($data2));

            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=0-15', 'If-Range' => date(DATE_RFC7231, $lastModifiedTime + 1)]]);
            Assert::same($response['statusCode'], 200);
            Assert::same(bin2hex($response['body']), bin2hex($data2));

            // head
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'method' => 'HEAD']);
            Assert::same($response['statusCode'], 200);
            Assert::isEmpty($response['body']);
            Assert::same($response['headers']['accept-ranges'], 'bytes');
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'method' => 'HEAD', 'headers' => ['Range' => 'bytes=0-15']]);
            Assert::same($response['statusCode'], 206);
            Assert::same('bytes 0-15/218787', $response['headers']['content-range']);
            Assert::isEmpty($response['body']);
            Assert::null($response['headers']['accept-ranges'] ?? null);

            // data boundary
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'abc']]);
            Assert::same($response['statusCode'], 200);
            Assert::same(bin2hex($response['body']), bin2hex($data2));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=abc']]);
            Assert::same($response['statusCode'], 416);
            Assert::isEmpty($response['body']);
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=-999999']]);
            Assert::same($response['statusCode'], 206);
            Assert::same(bin2hex($response['body']), bin2hex($data2));
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2, 'headers' => ['Range' => 'bytes=999999']]);
            Assert::same($response['statusCode'], 416);
            Assert::isEmpty($response['body']);
        });
    }
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Assert::true(swoole_mime_type_add('moc', 'application/x-mocha'));
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/',
        'static_handler_locations' => ['/static', '/']
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $response->end('hello world');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
