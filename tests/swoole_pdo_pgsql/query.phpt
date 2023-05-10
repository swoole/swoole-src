--TEST--
swoole_pdo_pgsql: test query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

const N = 10;

Co\run(static function (): void {
    pdo_pgsql_test_inc::init();
    $pdo = pdo_pgsql_test_inc::create();

    $stmt = $pdo->prepare('INSERT INTO ' . pdo_pgsql_test_inc::getTable() . ' (name, age) values (?, ?)');

    $list = [];
    for ($i = 0; $i < N; $i++) {
        $name = base64_encode(random_bytes(8));
        $age = random_int(18, 35);
        $stmt->bindValue(1, $name);
        $stmt->bindValue(2, $age);
        $stmt->execute();

        $list[] = [
            'id' => $pdo->lastInsertId(),
            'name' => $name,
            'age' => $age,
        ];
    }

    foreach ($list as $rs) {
        Co\go(function () use ($rs) {
            $pdo = pdo_pgsql_test_inc::create();
            $statement = $pdo->query('select * from ' . pdo_pgsql_test_inc::getTable() . ' where id = ' . $rs['id'] . ' limit 1');
            Assert::eq($statement->fetch(PDO::FETCH_ASSOC), $rs);
        });
    }
});

echo "Done\n";
?>
--EXPECTF--
Done
