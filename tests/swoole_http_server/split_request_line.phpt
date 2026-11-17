--TEST--
swoole_http_server: request line split across packets
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    foreach (["GET /index.php HT", "GET /index.php"] as $first) {
        $fp = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
        fwrite($fp, $first);
        usleep(100000);
        fwrite($fp, substr("GET /index.php HTTP/1.1", strlen($first)) . "\r\nHost: x\r\n\r\n");
        echo strtok(fgets($fp), "\r"), "\n";
        fclose($fp);
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', fn() => $pm->wakeup());
    $http->on('request', fn($req, $resp) => $resp->end($req->server['request_uri']));
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
HTTP/1.1 200 OK
HTTP/1.1 200 OK
