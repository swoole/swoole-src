--TEST--
swoole_http_server: http_autoindex
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        $files = scan_dir(DOCUMENT_ROOT);
        foreach ($files as $f) {
            Assert::contains($data, basename($f));
        }
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir1");
        $files = scan_dir(DOCUMENT_ROOT.'/dir1');
        foreach ($files as $f) {
            Assert::contains($data, basename($f));
        }
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir2");
        $files = scan_dir(DOCUMENT_ROOT.'/dir2');
        foreach ($files as $f) {
            Assert::contains($data, basename($f));
        }
        $pm->kill();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => DOCUMENT_ROOT,
        'http_autoindex' => true,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $response->end("dynamic request");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
