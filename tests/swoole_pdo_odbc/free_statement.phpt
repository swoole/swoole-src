--TEST--
swoole_pdo_odbc: freeing a statement does not block the event loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

// NO_CACHE: the driver reads rows from the server on demand, so freeing a statement whose
// result was not read to the end has to wait for the rest of it
define('DSN', 'odbc:DSN=' . substr(ODBC_DSN, strlen('odbc:')) . ';NO_CACHE=1');
const SLOW_ROWS = 'WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 200) '
    . "SELECT n, REPEAT('x', 2000) AS pad, SLEEP(0.005) AS s FROM seq";

$outside = null;

Co\run(static function () use (&$outside): void {
    $pdo = new PDO(DSN);
    $statement = $pdo->prepare(SLOW_ROWS);
    $statement->execute();
    Assert::eq((int) $statement->fetch(PDO::FETCH_ASSOC)['n'], 1);

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
    $statement = null;
    $during = $ticks - $before;
    $done = true;
    Assert::greaterThan($during, 10);

    Assert::eq((int) $pdo->query('SELECT 1')->fetchColumn(), 1);

    // freed after Co\run returns, outside of a coroutine
    $outside = $pdo->prepare('SELECT 2');
    $outside->execute();
    Assert::eq((int) $outside->fetchColumn(), 2);
});

$outside = null;

echo "Done\n";
?>
--EXPECTF--
Done
