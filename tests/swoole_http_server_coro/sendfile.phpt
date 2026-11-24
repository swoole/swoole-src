--TEST--
swoole_http_server_coro: sendfile
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$send_file_path = __DIR__ . '/sendfile.tmp';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $send_file_path) {
    for ($i = MAX_REQUESTS; $i--;) {
        $send_file = get_safe_random(mt_rand(0, 65535 * 10));
        file_put_contents($send_file_path, $send_file);
        $recv_file = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/test.jpg");
        Assert::same(md5($send_file), md5($recv_file));
    }
    file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/shutdown");
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $send_file_path) {
    go(function () use ($pm, $send_file_path) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
        });
        $server->handle('/test.jpg', function ($request, $response) use ($send_file_path) {
            $response->header('Content-Type', 'application/octet-stream');
            $response->header('Content-Disposition', 'attachment; filename=recvfile.txt');
            $response->sendfile($send_file_path);
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            echo "shutdown\n";
            $response->status(200);
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
unlink($send_file_path);
?>
--EXPECT--
shutdown
DONE
