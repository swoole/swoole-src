--TEST--
swoole_pdo_odbc: test query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 10;

Co\run(static function (): void {
    $pdo = new PDO(ODBC_DSN);

    $stmt = $pdo->prepare('INSERT INTO ckl (name, domain, path) values (?, ?, ?)');

    $list = [];
    for ($i = 0; $i < N; $i++) {
        $row = [
            'name' => base64_encode(random_bytes(8)),
            'domain' => 'domain-' . random_int(10000, 99999),
            'path' => '/' . uniqid() . '/' . $i,
        ];
        $list[] = $row;
        $stmt->bindValue(1, $row['name']);
        $stmt->bindValue(2, $row['domain']);
        $stmt->bindValue(3, $row['path']);
        $stmt->execute();
    }

    foreach ($list as $rs) {
        Co\go(function () use ($rs) {
            $pdo = new PDO(ODBC_DSN);
            $statement = $pdo->query('select name, domain, path from ckl where path = "' . $rs['path'] . '" limit 1');
            Assert::eq($statement->fetch(PDO::FETCH_ASSOC), $rs);
        });
    }
});

echo "Done\n";
?>
--EXPECTF--
Done
