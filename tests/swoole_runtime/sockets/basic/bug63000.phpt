--TEST--
swoole_runtime/sockets/basic: Multicast on OSX
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('skip sockets extension not available.');
}?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_bind($socket, '0.0.0.0', 31057);

$so = socket_set_option($socket, IPPROTO_IP, MCAST_JOIN_GROUP, array(
    "group" => '224.0.0.251',
    "interface" => 0,
));
var_dump($so);
});
?>
--EXPECT--
bool(true)
