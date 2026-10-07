--TEST--
swoole_pdo_pgsql: cancel a query that waits for its reply
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

Co\run(static function (): void {
    $pdo = pdo_pgsql_test_inc::create();
    $cid = Co\go(static function () use ($pdo): void {
        $start = microtime(true);
        try {
            $pdo->query('SELECT pg_sleep(5)');
            echo "returned\n";
        } catch (PDOException $e) {
            Assert::lessThan(microtime(true) - $start, 1);
            echo "canceled\n";
        }
    });
    Co::sleep(0.2);
    Assert::true(Co::cancel($cid));
    Co::sleep(0.1);
    // the rest of that reply would still arrive so the connection is closed
    try {
        $pdo->query('SELECT 1');
        echo "reused\n";
    } catch (PDOException $e) {
        echo "closed\n";
    }
    Assert::eq(pdo_pgsql_test_inc::create()->query('SELECT 1')->fetchColumn(), 1);
});

echo "Done\n";
?>
--EXPECT--
canceled
closed
Done
