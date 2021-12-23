--TEST--
swoole_socket_coro: import 4
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.0');
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function test($stream, $sock)
{
    if ($stream !== null) {
        echo "stream_set_blocking ";
        try {
            print_r(intval(stream_set_blocking($stream, 0)));
        } catch (Error $e) {
            echo get_class($e), ": ", $e->getMessage(), "\n";
        }
        echo "\n";
    }
    if ($sock !== null) {
        echo "socket_set_block ";
        try {
            print_r(intval(socket_set_block($sock)));
        } catch (Error $e) {
            echo get_class($e), ": ", $e->getMessage(), "\n";
        }
        echo "\n";
        echo "socket_get_option ";
        try {
            print_r(intval(socket_get_option($sock, SOL_SOCKET, SO_TYPE)));
        } catch (Error $e) {
            echo get_class($e), ": ", $e->getMessage(), "\n";
        }
        echo "\n";
    }
    echo "\n";
}

Co\run(function () {
    echo "normal\n";
    $stream0 = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
    $sock0 = Swoole\Coroutine\Socket::import($stream0);
    test($stream0, $sock0);

    echo "\nunset stream\n";
    $stream1 = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
    $sock1 = Swoole\Coroutine\Socket::import($stream1);
    unset($stream1);
    test(null, $sock1);

    echo "\nunset socket\n";
    $stream2 = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
    $sock2 = Swoole\Coroutine\Socket::import($stream2);
    unset($sock2);
    test($stream2, null);

    echo "\nclose stream\n";
    $stream3 = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
    $sock3 = Swoole\Coroutine\Socket::import($stream3);
    fclose($stream3);
    test($stream3, $sock3);

    echo "\nclose socket\n";
    $stream4 = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
    $sock4 = Swoole\Coroutine\Socket::import($stream4);
    socket_close($sock4);
    test($stream4, $sock4);

    echo "Done.\n";
});
?>
--EXPECTF--
normal
stream_set_blocking 1
socket_set_block 1
socket_get_option 2


unset stream
socket_set_block 1
socket_get_option 2


unset socket
stream_set_blocking 1


close stream
stream_set_blocking TypeError: stream_set_blocking(): supplied resource is not a valid stream resource

socket_set_block 1
socket_get_option 2


close socket
stream_set_blocking TypeError: stream_set_blocking(): supplied resource is not a valid stream resource

socket_set_block 0
socket_get_option 0

Done.
