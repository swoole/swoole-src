--TEST--
swoole_pdo_odbc: test hook pdo_odbc
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

Co\run(static function (): void {
    Co\go(function () {
        $pdo = new PDO(ODBC_DSN);
        $statement = $pdo->prepare('show tables');
        $statement->execute();
        Assert::greaterThan(count($statement->fetchAll(PDO::FETCH_COLUMN)), 1);
    });

    Co\go(function () {
        $pdo = new PDO(ODBC_DSN);
        $statement = $pdo->prepare('show tables');
        $statement->execute();
        Assert::greaterThan(count($statement->fetchAll(PDO::FETCH_COLUMN)), 1);
    });
});

echo "DONE\n";
?>
--EXPECTF--
DONE
