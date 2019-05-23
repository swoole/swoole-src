--TEST--
swoole_http_server: array header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--

<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {

        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->setHeaders([
            'Host' => "localhost",
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $cli->set([ 'timeout' => 1]);
        $cli->get('/');
        $data = $cli->recv();
       
        Assert::assert($cli->headers["lmnr"] === ["Linux","Nginx","Redis","Mysql"]);
        Assert::assert($cli->headers["language"] === ["C","C++","Java","PHP","Swoole"]);
        Assert::assert($cli->headers["key1"] === "key1_value");
        Assert::assert($cli->headers["key2"] === "key2_value");
    });
    swoole_event_wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'worker_num' => 1,
    ]);

    $http->on('request', function ($request, $response) {

        $response->header("lmnr", ["Linux","Nginx","Redis","Mysql"]);
        $response->header("language",["C","C++","Java","PHP","Swoole"]);
        $response->header("key1", "key1_value");
        $response->header("key2", "key2_value");
        $response->end("hello swoole");
    });
    $http->start();

};
$pm->childFirst();
$pm->run();

--EXPECT--
SUCCESS
