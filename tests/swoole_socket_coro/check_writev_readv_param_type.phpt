--TEST--
swoole_socket_coro: check writev and readv param type
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/bootstrap.php';

run(function () {
    $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    try {
        $iovector = [1];
        $conn->writeVectorAll($iovector);

    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

    try {
        $iovector = [1, '!'];
        $conn->readVectorAll($iovector);
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }
});

echo "DONE\n";
?>
--EXPECTF--
Item #[0] must be of type string, %s given
Item #[1] must be of type int, %s given
DONE
