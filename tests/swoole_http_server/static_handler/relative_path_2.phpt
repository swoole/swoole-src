--TEST--
swoole_http_server/static_handler: static handler with relative path [2]
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
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/../examples/test.jpg", ['http2' => $http2]);
            Assert::notEmpty($data);
            Assert::same(md5($data), md5_file(TEST_IMAGE));

            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/../docs/swoole-logo.svg", ['http2' => $http2]);
            Assert::eq("hello world", $data);
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
        'document_root' => SOURCE_ROOT_PATH . '/examples',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $response->end("hello world");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
