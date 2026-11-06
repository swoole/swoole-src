--TEST--
swoole_pdo_odbc: freeing a statement does not block the event loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

$outside = null;

Co\run(static function () use (&$outside): void {
    $pdo = new PDO(ODBC_DSN);
    // The server sends the second result 1 s after the first one. A statement freed after reading
    // the first result has to wait for the rest, whether the driver caches results or not.
    $pdo->exec('DROP PROCEDURE IF EXISTS swoole_odbc_free_statement');
    $pdo->exec('CREATE PROCEDURE swoole_odbc_free_statement() BEGIN SELECT 1 AS n; DO SLEEP(1); SELECT 2 AS n; END');

    foreach ([false, true] as $closeCursor) {
        $statement = $pdo->prepare('CALL swoole_odbc_free_statement()');
        $statement->execute();
        Assert::eq((int) $statement->fetchColumn(), 1);

        $ticks = 0;
        $done = false;
        Co\go(function () use (&$ticks, &$done) {
            while (!$done) {
                Co::sleep(0.001);
                $ticks++;
            }
        });
        Co::sleep(0.01);
        $before = $ticks;
        $begin = microtime(true);
        if ($closeCursor) {
            $statement->closeCursor();
        }
        $statement = null;
        $elapsed = microtime(true) - $begin;
        $during = $ticks - $before;
        $done = true;
        Assert::greaterThan($elapsed, 0.5);
        Assert::greaterThan($during, 10);

        Assert::eq((int) $pdo->query('SELECT 3')->fetchColumn(), 3);
    }

    $pdo->exec('DROP PROCEDURE swoole_odbc_free_statement');

    // freed after Co\run returns, outside of a coroutine
    $outside = $pdo->prepare('SELECT 4');
    $outside->execute();
    Assert::eq((int) $outside->fetchColumn(), 4);
});

$outside = null;

echo "Done\n";
?>
--EXPECTF--
Done
