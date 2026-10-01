--TEST--
swoole_pdo_sqlite: cancel connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;

Co\run(static function (): void {
    // The open runs in the thread pool and can't be interrupted, so it fails after the cancel.
    $cid = Co\go(static function (): void {
        try {
            new PDO('sqlite:/nonexistent/test.db');
        } catch (CanceledException $e) {
            echo "canceled\n";
        }
    });
    Assert::true(Coroutine::cancel($cid, true));
});
?>
--EXPECT--
canceled
