--TEST--
swoole_http_server: big data
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\Run(function () use ($pm) {
        $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
        var_dump($response['statusCode'] == 200);
        var_dump($response['body'] == str_repeat('A', 10 * 1024 * 1024));
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->end(str_repeat('A', 10 * 1024 * 1024));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
bool(true)
bool(true)