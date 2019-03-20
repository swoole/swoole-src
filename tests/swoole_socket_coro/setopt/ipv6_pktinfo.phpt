--TEST--
swoole_socket_coro: setOption IPV6_PKTINFO
--SKIPIF--
--FILE--
<?php
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
