--TEST--
swoole_http_server/static_handler: mimetype not exists
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use function  Swoole\Coroutine\Http\get;

define('TEST_DOCUMENT_ROOT', dirname(__DIR__, 3) . '/');
define('TEST_RANDOM_BYTES', random_bytes(rand(2048, 8192)));
const TEST_FILE = TEST_DOCUMENT_ROOT . '/examples/exists.xyz';

file_put_contents(TEST_FILE, TEST_RANDOM_BYTES);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        Assert::eq(get("http://127.0.0.1:{$pm->getFreePort()}/examples/not_exists.xyz")->getStatusCode(), 404);
        Assert::eq(get("http://127.0.0.1:{$pm->getFreePort()}/not_exists.xyz")->getStatusCode(), 500);

        $resp = get("http://127.0.0.1:{$pm->getFreePort()}/examples/exists.xyz");
        Assert::eq($resp->getBody(), TEST_RANDOM_BYTES);
        Assert::eq($resp->getHeaders()['content-type'], 'application/octet-stream');
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
        'document_root' => TEST_DOCUMENT_ROOT,
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
//unlink(TEST_FILE);
?>
--EXPECT--
DONE
