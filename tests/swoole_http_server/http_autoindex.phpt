--TEST--
swoole_http_server: http_autoindex
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
        $index_page_content = file_get_contents(DOCUMENT_ROOT . '/index_page.html');
        $dir1_index_page_content = file_get_contents(DOCUMENT_ROOT . '/dir1/index_page.html');
        $dir2_index_page_content = file_get_contents(DOCUMENT_ROOT . '/dir2/index_page.html');

        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::same($data, $index_page_content);
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir1");
        Assert::same($data, $dir1_index_page_content);
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/dir2");
        Assert::same($data, $dir2_index_page_content);

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
        'http_autoindex' => true,
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