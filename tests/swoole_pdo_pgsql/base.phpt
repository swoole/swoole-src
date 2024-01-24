--TEST--
swoole_pdo_pgsql: test hook pgsql
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

Co\run(static function (): void {
    pdo_pgsql_test_inc::init();
    Co\go(function () {
        $pdo = pdo_pgsql_test_inc::create();
        $statement = $pdo->prepare('SELECT * FROM pg_catalog.pg_tables limit 1');
        $statement->execute();
        var_dump($statement->fetchAll(PDO::FETCH_COLUMN));
    });

    Co\go(function () {
        $pdo = pdo_pgsql_test_inc::create();
        $statement = $pdo->prepare('SELECT * FROM pg_catalog.pg_tables limit 1');
        $statement->execute();
        var_dump($statement->fetchAll(PDO::FETCH_COLUMN));
    });
});

echo "Done\n";
?>
--EXPECTF--
array(1) {
  [0]=>
  string(%d) "%s"
}
array(1) {
  [0]=>
  string(%d) "%s"
}
Done
