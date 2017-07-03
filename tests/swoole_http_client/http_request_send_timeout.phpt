--TEST--
swoole_http_client: send timeout

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_http_client/http_request_send_timeout.php";

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/http_server_without_response.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

request_send_timeout(HTTP_SERVER_HOST, $port);
suicide(1000, SIGTERM, $closeServer);
?>

--EXPECT--
timeout