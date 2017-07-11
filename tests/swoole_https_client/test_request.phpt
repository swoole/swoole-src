--TEST--
swoole_https_client: test request
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
require_once __DIR__ . "/../include/api/swoole_http_client/simple_https_client.php";

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_https_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

request(HTTP_SERVER_HOST, $port, "GET", "/", null,
    ["cookie_key" => "cookie_value"],
    ["header_key" => "header_value"],
    function(swoole_http_client $cli) use($closeServer) {
        assert($cli->body === "Hello World!");
        echo "SUCCESS";$closeServer();
    });

suicide(1000, SIGTERM, $closeServer);
?>
--EXPECT--
SUCCESS
