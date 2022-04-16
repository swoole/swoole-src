--TEST--
swoole_socket_coro: import 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.0');
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    var_dump(Swoole\Coroutine\Socket::import(fopen(__FILE__, "rb")));
    try {
        Swoole\Coroutine\Socket::import(socket_create(AF_INET, SOCK_DGRAM, SOL_UDP));
    } catch (TypeError $e) {
        echo $e->getMessage(), "\n";
    }
    $s = stream_socket_server("udp://127.0.0.1:0", $errno, $errstr, STREAM_SERVER_BIND);
    var_dump($s);
    var_dump(fclose($s));
    try {
        Swoole\Coroutine\Socket::import($s);
    } catch (TypeError $e) {
        echo $e->getMessage(), "\n";
    }

    echo "Done.";
});
?>
--EXPECTF--
Warning: Swoole\Coroutine\Socket::import(): Cannot represent a stream of type %s as a Socket Descriptor in %s on line %d
bool(false)
Swoole\Coroutine\Socket::import(): Argument #1 ($stream) must be of type resource, %s given
resource(%d) of type (stream)
bool(true)
Swoole\Coroutine\Socket::import(): supplied resource is not a valid stream resource
Done.
