--TEST--
swoole_http_client: execute without method and content

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
require_once __DIR__ . "/../include/api/swoole_http_client/simple_http_client.php";

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());


$httpClient = new \swoole_http_client("115.239.210.27", "80");
$httpClient->setData("null");
$r = $httpClient->execute("/", function(\swoole_http_client $httpClient) {
    echo "SUCCESS";
    $httpClient->close();
});

?>

--EXPECT--
SUCCESS