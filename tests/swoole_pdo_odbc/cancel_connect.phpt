--TEST--
swoole_pdo_odbc: cancel connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;

Co\run(static function (): void {
    // The connect runs in the thread pool and can't be interrupted, so it fails after the cancel.
    $cid = Co\go(static function (): void {
        try {
            new PDO(ODBC_DSN, 'nonexistent', 'nonexistent');
        } catch (CanceledException $e) {
            echo "canceled\n";
        }
    });
    Assert::true(Coroutine::cancel($cid, true));
});
?>
--EXPECT--
canceled
