--TEST--
swoole_http_server/static_handler: static handler with relative path
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    foreach ([false, true] as $http2) {
        Swoole\Coroutine\run(function () use ($pm, $http2) {
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/examples/test.jpg", ['http2' => $http2]);
            Assert::notEmpty($data);
            Assert::same(md5($data), md5_file(TEST_IMAGE));

            /**
             * 命中location，但文件不存在，直接返回 404
             */
            $status = httpGetStatusCode("http://127.0.0.1:{$pm->getFreePort()}/examples/test2.jpg", ['http2' => $http2]);
            Assert::same($status, 404);

            /**
             * 动态请求
             */
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test.jpg", ['http2' => $http2]);
            Assert::same($data, TEST_IMAGE);
        });
    }
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => __DIR__ . '/../../../',
        'static_handler_locations' => ['/examples']
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $response->end(TEST_IMAGE);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
