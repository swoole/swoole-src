--TEST--
swoole_https_client: get_with_query
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

$sm = new ServerManager(__DIR__ . "/../include/api/swoole_http_server/simple_https_server.php");
$sm->listen(HTTP_SERVER_HOST);
$closeServer = $sm->run();

testHttpsGet(HTTP_SERVER_HOST, $sm->port, $_SERVER, function() use($closeServer) {
    echo "SUCCESS";$closeServer();
});

suicide(1000, SIGKILL, $closeServer);
?>
--EXPECT--
SUCCESS
