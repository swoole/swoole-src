--TEST--
swoole_http_server: compress response by http client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpRequest("http://127.0.0.1:{$pm->getFreePort()}", ['headers' => ['accept-encoding' => 'br']]);
        $headers = $data['headers'];
        Assert::assert(!empty($headers));
        Assert::eq($headers['content-encoding'], 'gzip');
        Assert::eq($data['body'], file_get_contents(TEST_IMAGE));
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function ($request, $response) {
        $gzipEncoded = gzencode(file_get_contents(TEST_IMAGE), 9, FORCE_GZIP);
        $response->setHeader('Content-Encoding', 'gzip');
        $response->end($gzipEncoded);
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
