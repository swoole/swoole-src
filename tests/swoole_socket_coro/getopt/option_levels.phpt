--TEST--
swoole_socket_coro: socket options are interpreted at their protocol level
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Socket;

Swoole\Coroutine\run(static function () {
    $udp = new Socket(AF_INET, SOCK_DGRAM, SOL_UDP);
    // Linux IP_RECVTOS (13) collides with SO_LINGER; SO_NO_CHECK (11) collides with TCP_INFO.
    foreach ([0, 1] as $value) {
        Assert::true($udp->setOption(IPPROTO_IP, 13, $value));
        Assert::same($udp->getOption(IPPROTO_IP, 13), $value);
        Assert::true($udp->setOption(SOL_SOCKET, 11, $value));
        Assert::same($udp->getOption(SOL_SOCKET, 11), $value);
    }
    Assert::false(@$udp->getOption(SOL_TCP, TCP_INFO));
    $udp->close();

    $tcp = new Socket(AF_INET, SOCK_STREAM, SOL_TCP);
    // TCP_NOTSENT_LOWAT (25) must take an integer, despite colliding with SO_BINDTODEVICE.
    Assert::true($tcp->setOption(SOL_TCP, 25, 4096));
    Assert::same($tcp->getOption(SOL_TCP, 25), 4096);
    Assert::true($tcp->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 5]));
    Assert::same($tcp->getOption(SOL_SOCKET, SO_LINGER), ['l_onoff' => 1, 'l_linger' => 5]);
    Assert::true($tcp->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 250000]));
    Assert::same($tcp->getOption(SOL_SOCKET, SO_RCVTIMEO), ['sec' => 1, 'usec' => 250000]);
    Assert::isArray($tcp->getOption(SOL_TCP, TCP_INFO));
    $tcp->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
