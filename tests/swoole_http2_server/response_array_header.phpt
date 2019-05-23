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

        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());

        $cli->set([ 'timeout' => 1, 'package_max_length' => 1024*1024*8]);
        $cli->connect();

        $req = new Swoole\Http2\Request;
        $req->path = "/index.html";
        $req->headers = [
            'host' => "localhost",
            "user-agent" => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
            'accept-encoding' => 'gzip',
        ];
        $cli->send($req);
        $resp = $cli->recv();
       
        Assert::assert($resp->headers["lmnr"] === ["Linux","Nginx","Redis","Mysql"]);
        Assert::assert($resp->headers["language"] === ["C","C++","Java","PHP","Swoole"]);
        Assert::assert($resp->headers["key1"] === "key1_value");
        Assert::assert($resp->headers["key2"] === "key2_value");
    });
    swoole_event_wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'worker_num' => 1,
        'open_http2_protocol' => 1,
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
