--TEST--
swoole_coroutine/cancel: waitEvent
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

// An idle local connection provides a readable event to wait for without DNS,
// Internet access, or data from an external HTTP server racing cancellation.
$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errmsg);
Assert::assert($listener !== false, $errmsg);
$address = stream_socket_get_name($listener, false);
$fp = stream_socket_client('tcp://' . $address, $errno, $errmsg, 5);
Assert::assert($fp !== false, $errmsg);
$peer = stream_socket_accept($listener, 5);
Assert::assert($peer !== false);
fclose($listener);

run(function () use ($fp) {
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        System::sleep(0.002);
        Assert::true(Coroutine::cancel($cid));
    });

    $retval = System::waitEvent($fp);
    echo "Done\n";
    Assert::eq($retval, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
});

fclose($fp);
fclose($peer);
?>
--EXPECT--
Done
