--TEST--
swoole_http2_server: 413
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_nghttp();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $file = tempnam('/tmp', 'swoole_http2_');
    file_put_contents($file, str_repeat('A', 2 * 1024 * 1024));
    Assert::assert(empty($res = `nghttp -d {$file} https://127.0.0.1:{$pm->getFreePort()}/ > /dev/stdout 2>/dev/null`));
    $pm->kill();
    unlink($file);
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'package_max_length' => 1024 * 1024,
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key'
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end($request->getContent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
