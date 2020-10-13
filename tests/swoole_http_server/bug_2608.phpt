--TEST--
swoole_http_server: bug #2608
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Coroutine;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    foreach ([false, true] as $http2) {
        Coroutine\run(function () use ($pm, $http2) {
            $data = httpGetBody(
                "http://127.0.0.1:{$pm->getFreePort()}/examples/test.jpg",
                ['http2' => $http2]
            );
            Assert::assert(!empty($data));
            Assert::assert(md5($data) === md5_file(TEST_IMAGE));

            $data = httpGetBody(
                "http://127.0.0.1:{$pm->getFreePort()}/../../examples/test.jpg",
                ['http2' => $http2]
            );
            Assert::same($data, "hello world");
        });
    }
    $pm->kill();
    unlink(__DIR__ . '/examples');
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => __DIR__,
        'static_handler_locations' => ["/examples",]
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        if (!file_exists(__DIR__ . '/examples')) {
            symlink(dirname(dirname(__DIR__)) . '/examples/', __DIR__ . '/examples');
        }
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $response->end('hello world');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
DONE
