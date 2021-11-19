--TEST--
Test socket_addrinfo_connect()
--SKIPIF--
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$addrinfo = socket_addrinfo_lookup('127.0.0.1', 2000, array(
    'ai_family' => AF_INET,
    'ai_socktype' => SOCK_DGRAM,
));
var_dump(socket_addrinfo_connect($addrinfo[0]));
echo "Done";
});
?>
--EXPECT--
object(Swoole\Coroutine\Socket)#2 (0) {
}
Done
