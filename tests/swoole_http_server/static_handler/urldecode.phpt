--TEST--
swoole_http_server/static_handler: http url decode (#2676)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;

$pm = new ProcessManager;
$filename = 'PHP是世界上最好的语言.txt';
$filepath = __DIR__ . '/' . $filename;
$content = get_safe_random();
file_put_contents($filepath, $content);
register_shutdown_function(function () use ($filepath) {
    @unlink($filepath);
});
$pm->parentFunc = function () use ($pm, $filename, $content) {
    foreach ([false, true] as $http2) {
        Coroutine\run(function () use ($pm, $http2, $filename, $content) {
            $data = httpGetBody(
                "http://127.0.0.1:{$pm->getFreePort()}/" . urlencode($filename),
                ['http2' => $http2]
            );
            Assert::same($data, $content);
        });
    }
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => __DIR__
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        var_dump('never here');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
