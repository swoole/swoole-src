--TEST--
swoole_http2_server: nghttp2 big data with ssl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (strpos(`nghttp --version 2>&1`, 'nghttp2') === false) {
    skip('no nghttp');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $file = __DIR__ . '/../../benchmark/post.big.data';
    if (Assert::assert(!empty($res = `nghttp -d {$file} https://127.0.0.1:{$pm->getFreePort()}/ > /dev/stdout 2>/dev/null`))) {
        Assert::same(md5($res), md5_file($file));
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key'
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end($request->rawcontent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
