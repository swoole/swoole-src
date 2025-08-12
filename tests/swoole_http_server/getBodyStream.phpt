--TEST--
swoole_http_server: getBodyStream
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Co\run;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $randomData = get_safe_random();
        $cli = new Co\http\Client(HTTP_SERVER_HOST, $pm->getFreePort(), false);
        $cli->setMethod('POST');
        $cli->setData($randomData);
        $ok = $cli->execute('/getBodyStream');
        Assert::assert($ok);
        Assert::same($cli->statusCode, 200);
        Assert::same($cli->errCode, 0);
        Assert::same($cli->body, $randomData);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $stream = $request->getBodyStream();
        $response->end(stream_get_contents($stream));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
