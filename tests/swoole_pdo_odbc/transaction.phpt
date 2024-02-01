--TEST--
swoole_pdo_odbc: test query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';



Co\run(static function (): void {
    $pdo = new PDO(ODBC_DSN);

    $insertToTable = function ($pdo) {
        $stmt = $pdo->prepare('INSERT INTO ckl (name, domain, path) values (?, ?, ?)');
        $row = [
            'name' => base64_encode(random_bytes(8)),
            'domain' => 'domain-' . random_int(10000, 99999),
            'path' => '/' . uniqid() . '/' . 0,
        ];
        $stmt->bindValue(1, $row['name']);
        $stmt->bindValue(2, $row['domain']);
        $stmt->bindValue(3, $row['path']);
        $stmt->execute();
    };

    $countTable = function ($pdo) {
        return $pdo->query('select count(*) c from ckl')->fetch(PDO::FETCH_ASSOC)['c'];
    };

    $insertToTable($pdo);
    var_dump('insert');

    $c1 = $countTable($pdo);

    $pdo->beginTransaction();
    $insertToTable($pdo);
    $pdo->rollBack();
    var_dump('rollback');

    Assert::eq($countTable($pdo), $c1);

    $pdo->beginTransaction();
    $insertToTable($pdo);
    $pdo->commit();
    var_dump('commit');

    Assert::eq($countTable($pdo), $c1 + 1);
});

echo "Done\n";
?>
--EXPECTF--
string(6) "insert"
string(8) "rollback"
string(6) "commit"
Done
