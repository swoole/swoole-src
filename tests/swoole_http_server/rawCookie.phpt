--TEST--
swoole_http_response: rawcooki

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
require_once __DIR__ . "/../include/api/swoole_http_client/simple_http_client.php";

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

$rawcontent = "HELLO";
testRawCookie(HTTP_SERVER_HOST, $port, $rawcontent, function(\swoole_http_client $cli) use($closeServer, $rawcontent) {
    assert($cli->headers["set-cookie"] === "rawcontent=$rawcontent");
    echo "SUCCESS";
    $closeServer();
});

suicide(1000, SIGTERM, $closeServer);
?>
--EXPECT--
SUCCESS