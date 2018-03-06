<?php

require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_websocket_server/send_large_request_data.php";

$swoole_websocket_server = __DIR__ . "/../include/api/swoole_websocket_server/swoole_websocket_server.php";
$closeServer = start_server($swoole_websocket_server, WEBSOCKET_SERVER_HOST, $port = get_one_free_port());

send_large_request_data(WEBSOCKET_SERVER_HOST, $port);
echo "SUCCESS";

suicide(1000, SIGTERM, $closeServer);
?>
