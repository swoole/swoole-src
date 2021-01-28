--TEST--
swoole_http_server: sendfile with ssl
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = MAX_REQUESTS; $i--;) {
        $send_file = get_safe_random(mt_rand(0, 65535 * 10));
        file_put_contents('/tmp/sendfile.txt', $send_file);

        $ctxArr = [
            'verify_peer' => false,
        ];
        $ctx = stream_context_create(['ssl' => $ctxArr]);
        $recv_file = file_get_contents("https://127.0.0.1:{$pm->getFreePort()}", false, $ctx);
        Assert::same($send_file, $recv_file);
    }
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->header('Content-Type', 'application/octet-stream');
        $response->header('Content-Disposition', 'attachment; filename=recvfile.txt');
        $response->sendfile('/tmp/sendfile.txt');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
