--TEST--
swoole_websocket_server: test server with small data
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_websocket_server/send_small_request_data.php";

$swoole_websocket_server = __DIR__ . "/../include/api/swoole_websocket_server/swoole_websocket_server.php";
$closeServer = start_server($swoole_websocket_server, WEBSOCKET_SERVER_HOST, $port = get_one_free_port());

send_small_request_data(WEBSOCKET_SERVER_HOST, $port);
echo "SUCCESS";

suicide(1000, SIGTERM, $closeServer);
?>
--EXPECT--
SUCCESS
