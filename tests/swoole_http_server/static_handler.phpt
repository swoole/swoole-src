--TEST--
swoole_http_server: static file handler
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
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2]);
            Assert::assert(!empty($data));
            $data2 = file_get_contents(TEST_IMAGE);
            for ($i = 0; $i < strlen($data); $i++) {
                if (!isset($data2[$i])) {
                    echo "no index {$i}\n";
                    var_dump(substr($data, $i));
                    break;
                }
                if ($data[$i] != $data2[$i]) {
                    var_dump($i);
                    break;
                }
            }
            Assert::same(md5($data), md5_file(TEST_IMAGE));

            #3084
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/http/empty.txt");
            Assert::same($response['statusCode'], 200);
            Assert::isEmpty($response['body']);

            #3131
            $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/http/moc.moc");
            Assert::same($response['statusCode'], 200);
            Assert::same($response['body'], file_get_contents(__DIR__ . '/../../examples/http/moc.moc'));
            Assert::same($response['headers']['content-type'], 'application/x-mocha');
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
