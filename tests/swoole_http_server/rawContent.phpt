--TEST--
swoole_http_server: raw-content
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
        $httpClient = new Co\http\Client(HTTP_SERVER_HOST, $pm->getFreePort(), false);
        $httpClient->setMethod("POST");
        $httpClient->setData($randomData);

        $ok = $httpClient->execute("/rawContent");
        Assert::assert($ok);
        Assert::same($httpClient->statusCode, 200);
        Assert::same($httpClient->errCode, 0);
        Assert::same($httpClient->body, $randomData);

        $ok = $httpClient->execute("/getContent");
        Assert::assert($ok);
        Assert::same($httpClient->statusCode, 200);
        Assert::same($httpClient->errCode, 0);
        Assert::same($httpClient->body, $randomData);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        if ($request->server['request_uri'] === '/rawContent') {
            $response->end($request->rawContent());
        } else {
            $response->end($request->getContent());
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
