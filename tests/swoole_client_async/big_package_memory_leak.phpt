--TEST--
swoole_client: big_package_memory_leak

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

$tcp_server = __DIR__ . "/../../memoryleak/tcp_client_memory_leak/tcp_serv.php";
start_server($tcp_server, "127.0.0.1", 9001);

$mem = memory_get_usage(true);
require_once __DIR__ . "/../../memoryleak/tcp_client_memory_leak/tcp_client.php";
assert(memory_get_usage(true) == $mem);
echo "SUCCESS";
?>

--EXPECT--
SUCCESS