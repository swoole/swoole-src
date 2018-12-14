--TEST--
swoole_http_client: execute without method and content

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/simple_http_client.php';

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