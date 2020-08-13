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

symlink(TEST_IMAGE, TEST_LINK_IMAGE);
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
            $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/examples/test_link.jpg");
            if (is_file(TEST_LINK_IMAGE)) {
                unlink(TEST_LINK_IMAGE);
            }
            Assert::assert(md5($data) === md5_file(TEST_IMAGE));
    });
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
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
