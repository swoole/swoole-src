--TEST--
swoole_http_server/static_handler: static handler with locations
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
        });
    }
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(dirname(__DIR__))) . '/',
        'static_handler_locations' => ['/examples']
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $response->end(TEST_IMAGE);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
