--TEST--
swoole_http_server_coro: sendfile delete_file removes the file after the synchronous send
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$path    = tempnam('/tmp', 'swoole_coro_sendfile_delete_');
$content = get_safe_random(256 * 1024);
file_put_contents($path, $content);

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $path, $content) {
    $body = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/download");
    Assert::same(md5($body), md5($content));

    // The coroutine socket send is synchronous, so the file is deleted by the time the
    // body has been received; poll within a deadline to absorb scheduling.
    for ($i = 0; $i < 200; $i++) {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            break;
        }
        usleep(25 * 1000);
    }
    clearstatcache(true, $path);
    Assert::false(is_file($path));

    file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/shutdown");
    echo "DONE\n";
    @unlink($path);
};
$pm->childFunc = function () use ($pm, $path) {
    go(function () use ($pm, $path) {
        $server = new Co\Http\Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/download', function ($request, $response) use ($path) {
            $response->header('Content-Type', 'application/octet-stream');
            $response->sendfile($path, 0, 0, true);
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->end();
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    Swoole\Event::wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
