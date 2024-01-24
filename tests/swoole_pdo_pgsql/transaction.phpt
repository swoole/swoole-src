--TEST--
swoole_pdo_pgsql: test query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

Co\run(static function (): void {
    pdo_pgsql_test_inc::init();
    $pdo = pdo_pgsql_test_inc::create();

    $stmt = $pdo->prepare('INSERT INTO ' . pdo_pgsql_test_inc::getTable() . ' (name, age) values (?, ?)');
    $stmt->bindValue(1, base64_encode(random_bytes(8)));
    $stmt->bindValue(2, random_int(18, 35));
    $stmt->execute();

    var_dump('insert');

    Co::join([Co\go(static function (): void {
        $pdo = pdo_pgsql_test_inc::create();
        try {
            $pdo->beginTransaction();

            $pdo->exec('DROP TABLE IF EXISTS ' . pdo_pgsql_test_inc::getTable());
            throw new Exception('interrupt!!!');
            $pdo->commit();
        } catch (\Exception $e) {
            $pdo->rollBack();
            var_dump('rollback');
        }
    })]);

    var_dump('wait1');
    var_dump(pdo_pgsql_test_inc::tableExists($pdo, pdo_pgsql_test_inc::getTable()));

    Co::join([Co\go(static function (): void {
        $pdo = pdo_pgsql_test_inc::create();
        try {
            $pdo->beginTransaction();

            $pdo->exec('DROP TABLE IF EXISTS ' . pdo_pgsql_test_inc::getTable());
            $pdo->commit();
        } catch (\Exception $e) {
            $pdo->rollBack();
            var_dump($e->getMessage());
        }
    })]);

    var_dump('wait2');
    var_dump(pdo_pgsql_test_inc::tableExists($pdo, pdo_pgsql_test_inc::getTable()));
});

echo "Done\n";
?>
--EXPECTF--
string(6) "insert"
string(8) "rollback"
string(5) "wait1"
bool(true)
string(5) "wait2"
bool(false)
Done
