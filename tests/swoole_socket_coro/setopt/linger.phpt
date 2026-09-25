--TEST--
swoole_socket_coro/setopt: setOption SO_LINGER
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);

Assert::true($socket->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 5]));
Assert::true($socket->setOption(SOL_SOCKET, SO_LINGER, (object) ['l_onoff' => 1, 'l_linger' => 5]));

try {
    $socket->setOption(SOL_SOCKET, SO_LINGER, 1);
} catch (TypeError $e) {
    echo $e->getMessage(), "\n";
}

try {
    $socket->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 65536, 'l_linger' => 0]);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n";
}

try {
    $socket->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 65536]);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n";
}

try {
    $socket->setOption(SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => -1]);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n";
}
?>
--EXPECT--
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) must be of type array|object when argument $opt_name is SO_LINGER, int given
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) "l_onoff" must be between 0 and 65535
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) "l_linger" must be between 0 and 65535
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) "l_linger" must be between 0 and 65535
