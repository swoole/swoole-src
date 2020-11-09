--TEST--
swoole_socket_coro: writeVector with ssl
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

run(function () {
    $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $conn->connect('127.0.0.1', 9501);

    $conn->setProtocol([
        'open_ssl' => true,
    ]);

    $iov = ['hello', 'world'];

    try {
        $conn->writeVector($iov);
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

    try {
        $conn->writeVectorAll($iov);
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

    echo "DONE\n";
});
?>
--EXPECT--
Use writeVector or writeVectorAll in ssl is not supported
Use writeVector or writeVectorAll in ssl is not supported
DONE
