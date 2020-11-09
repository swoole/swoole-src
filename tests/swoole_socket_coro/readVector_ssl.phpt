--TEST--
swoole_socket_coro: readVector with ssl
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
        $conn->readVector($iov);
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

    try {
        $conn->readVectorAll($iov);
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

    echo "DONE\n";
});
?>
--EXPECT--
Use readVector or readVectorAll in ssl is not supported
Use readVector or readVectorAll in ssl is not supported
DONE
