--TEST--
swoole_http_server: rawcontent

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/simple_http_client.php';

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

$payload = RandStr::gen(1024 * 1024);
testRawcontent(HTTP_SERVER_HOST, $port, $payload, function(\swoole_http_client $cli) use($closeServer, $payload) {
    assert($cli->body === $payload);
    echo "SUCCESS\n";
    $closeServer();
});
swoole_event::wait();
?>
--EXPECT--
SUCCESS