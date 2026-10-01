--TEST--
swoole_pdo_oracle: cancel connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;

Co\run(static function (): void {
    // The login runs in the thread pool and can't be interrupted, so it fails after the cancel.
    $cid = Co\go(static function (): void {
        try {
            new PDO(ORACLE_TNS, 'nonexistent', 'nonexistent');
        } catch (CanceledException $e) {
            echo "canceled\n";
        }
    });
    Assert::true(Coroutine::cancel($cid, true));
});
?>
--EXPECT--
canceled
