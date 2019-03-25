--TEST--
swoole_socket_coro/setopt: setOption IPV6_PKTINFO
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET6, SOCK_DGRAM, SOL_UDP);

var_dump(@$socket->setOption(IPPROTO_IPV6, IPV6_PKTINFO, []));
var_dump($socket->setOption(IPPROTO_IPV6, IPV6_PKTINFO, [
    "addr" => '::1',
    "ifindex" => 0
]));

?>
--EXPECTF--
bool(false)
bool(true)
