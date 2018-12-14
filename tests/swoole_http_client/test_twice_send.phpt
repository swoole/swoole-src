--TEST--
swoole_http_client: test twice send
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/simple_http_client.php';

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

testBigBodyMethodNotSupport2(HTTP_SERVER_HOST, $port, function() use($closeServer) {
    $closeServer();
});

suicide(2500, SIGTERM, $closeServer);
?>
--EXPECT--
SUCCESSclose
