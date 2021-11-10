--TEST--
swoole_feature/cross_close: stream
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\System;

Swoole\Runtime::enableCoroutine();
run(function () {
    $fp = stream_socket_client('tcp://' . REDIS_SERVER_HOST . ':' . REDIS_SERVER_PORT, $errno, $errstr, 1);
    if (!$fp) {
        exit("$errstr ($errno)\n");
    } else {
        go(function () use ($fp) {
            System::sleep(0.001);
            echo "CLOSE\n";
            fclose($fp);
            echo "DONE\n";
        });
        echo "READ\n";
        Assert::assert(!fread($fp, 1024));
        echo "CLOSED\n";
        fclose($fp);
    }
});
?>
--EXPECTF--
READ
CLOSE
CLOSED

Warning: fclose(): supplied resource is not a valid stream resource in %s/tests/swoole_feature/cross_close/stream.php on line %d
DONE
