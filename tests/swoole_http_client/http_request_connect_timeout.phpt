--TEST--
swoole_http_client: connect timeout

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_http_server = __DIR__ . "/../include/api/swoole_http_client/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

require __DIR__ . '/../include/api/swoole_http_client/http_request_connect_timeout.php';
?>
--EXPECT--
