--TEST--
swoole_http_server: http_index_files
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $index_content = file_get_contents(DOCUMENT_ROOT . '/index.html');
        $dir2_index_txt_content = file_get_contents(DOCUMENT_ROOT . '/dir2/index.txt');

        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::same($data, $index_content);
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir1");
        Assert::same($data, 'dynamic request');
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir2");
        Assert::assert($data, $dir2_index_txt_content);

        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => DOCUMENT_ROOT,
        'http_index_files' => ['index.html', 'index.txt'],
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (Request $request, Response $response) {
        $response->end("dynamic request");
    });

    $http->start();

};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
