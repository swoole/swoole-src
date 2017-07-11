--TEST--
swoole_client: big_package_memory_leak

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

$tcp_server = __DIR__ . "/../include/memoryleak/tcp_client_memory_leak/tcp_serv.php";
$closeServer = start_server($tcp_server, "127.0.0.1", 9001);

$mem = memory_get_usage(true);
fclose(STDOUT);
ini_set("memory_limit", "100m");
$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function (swoole_client $cli)
{
    $cli->send(str_repeat("\0", 1024 * 1024 * 1.9));
});
$cli->on("receive", function (swoole_client $cli, $data)
{
    $cli->send($data);
});
$cli->on("error", function (swoole_client $cli)
{
    echo "error";
});
$cli->on("close", function (swoole_client $cli) use ($closeServer)
{
    echo "closed\n";
    $closeServer();
});
$cli->connect("127.0.0.1", 9001);
assert(memory_get_usage(true) == $mem);
echo "SUCCESS";
?>

--EXPECT--
SUCCESS
closed
