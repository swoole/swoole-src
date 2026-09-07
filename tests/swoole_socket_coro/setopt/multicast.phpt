--TEST--
swoole_socket_coro/setopt: multicast
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_darwin();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET, SOCK_DGRAM, SOL_UDP);
$socket->bind('0.0.0.0', 9905);

$ret = $socket->setOption(IPPROTO_IP, MCAST_JOIN_GROUP, array(
    'group' => '224.10.20.30',
    'interface' => 0
));

if ($ret === false)
{
    throw new RuntimeException('Unable to join multicast group');
}
Assert::true($socket->setOption(IPPROTO_IP, IP_MULTICAST_LOOP, true));

go(function () use ($socket) {
    $n = 10;
    while($n--) {
        $addr = [];
        $data = $socket->recvfrom($addr);
        Assert::assert(strlen($data) > 10);
        Assert::assert(!empty($addr['port']));
        Assert::assert(!empty($addr['address']));
    }
});

go(function () use ($socket) {
    $n = 10;
    while($n--) {
        Assert::greaterThan($socket->sendto('224.10.20.30', 9905, "hello world [$n]\n"), 0);
        co::sleep(.03);
    }
});

Swoole\Event::wait();

?>
--EXPECTF--
