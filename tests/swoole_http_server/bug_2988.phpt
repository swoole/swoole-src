--TEST--
swoole_http_server: bug Github#2988
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const ILLEGAL_REQUEST = "GET / HTTP/1.1\r\nAccept: gzip\r\n\r\n";

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (Assert::true($client->connect('127.0.0.1', $pm->getFreePort()))) {
            if (Assert::eq($client->sendAll(ILLEGAL_REQUEST), strlen(ILLEGAL_REQUEST))) {
                $response = $client->recv();
                phpt_var_dump($response);
                Assert::contains($response, $pm->getRandomData());
            }
        }
    });
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->end($pm->getRandomData());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
SUCCESS
