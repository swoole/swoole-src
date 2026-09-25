--TEST--
swoole_socket_coro/setopt: setOption SO_RCVTIMEO / SO_SNDTIMEO
--DESCRIPTION--
-invalid params
-array/object params
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);

try {
    $socket->setOption(SOL_SOCKET, SO_RCVTIMEO, 1);
} catch (TypeError $e) {
    echo $e->getMessage(), "\n";
}

try {
    $socket->setOption(SOL_SOCKET, SO_SNDTIMEO, 1);
} catch (TypeError $e) {
    echo $e->getMessage(), "\n";
}

$retval_1 = $socket->setOption(SOL_SOCKET, SO_RCVTIMEO, array());
Assert::false($retval_1);
$options = array("sec" => 1, "usec" => 0);
$retval_2 = $socket->setOption(SOL_SOCKET, SO_RCVTIMEO, $options);
Assert::true($retval_2);
Assert::true($socket->setOption(SOL_SOCKET, SO_RCVTIMEO, (object) $options));
Assert::true($socket->setOption(SOL_SOCKET, SO_SNDTIMEO, (object) $options));

?>
--EXPECTF--
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) must be of type array|object when argument $opt_name is SO_RCVTIMEO, int given
Swoole\Coroutine\Socket::setOption(): Argument #3 ($opt_value) must be of type array|object when argument $opt_name is SO_SNDTIMEO, int given

Warning: Swoole\Coroutine\Socket::setOption(): no key "sec" passed in optval in %s on line %d
