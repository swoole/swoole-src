--TEST--
swoole_http_server_coro: sendfile
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($i = MAX_REQUESTS; $i--;) {
        $send_file = get_safe_random(mt_rand(0, 65535 * 10));
        file_put_contents('/tmp/sendfile.txt', $send_file);
        $recv_file = file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/test.jpg");
        Assert::same(md5($send_file), md5($recv_file));
    }
    file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/shutdown");
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
        });
        $server->handle('/test.jpg', function ($request, $response) {
            $response->header('Content-Type', 'application/octet-stream');
            $response->header('Content-Disposition', 'attachment; filename=recvfile.txt');
            $response->sendfile('/tmp/sendfile.txt');
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
    swoole_event_wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
shutdown
DONE
