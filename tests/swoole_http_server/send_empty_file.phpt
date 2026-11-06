--TEST--
swoole_http_server: send empty file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;

$keep_path   = tempnam('/tmp', 'swoole_empty_keep_');
$delete_path = tempnam('/tmp', 'swoole_empty_delete_');
file_put_contents($keep_path, '');
file_put_contents($delete_path, '');

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $keep_path, $delete_path) {
    Co\run(function () use ($pm, $keep_path, $delete_path) {
        // An empty file sends an empty body; the default keeps the file.
        Assert::same(httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/keep"), '');
        clearstatcache(true, $keep_path);
        Assert::true(is_file($keep_path));

        // delete_file removes the empty file at the terminal response boundary, where the
        // transport callback is never invoked.
        Assert::same(httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/delete"), '');
        $gone = false;
        for ($i = 0; $i < 200; $i++) {
            clearstatcache(true, $delete_path);
            if (!is_file($delete_path)) {
                $gone = true;
                break;
            }
            System::sleep(0.025);
        }
        Assert::true($gone);
    });
    echo "DONE\n";
    $pm->kill();
    @unlink($keep_path);
    @unlink($delete_path);
};
$pm->childFunc = function () use ($pm, $keep_path, $delete_path) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use (
        $keep_path,
        $delete_path
    ) {
        if ($request->server['request_uri'] === '/delete') {
            $response->sendfile($delete_path, 0, 0, true);
        } else {
            $response->sendfile($keep_path);
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
