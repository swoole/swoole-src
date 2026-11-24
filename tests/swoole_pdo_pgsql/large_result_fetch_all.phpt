--TEST--
swoole_pdo_pgsql: fetchAll preserves five million rows in a large result
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';

const ROW_COUNT = 5000000;
ini_set('memory_limit', '3G');
Assert::setThrowException(true);

Swoole\Coroutine::set(['hook_flags' => SWOOLE_HOOK_PDO_PGSQL]);
Swoole\Coroutine\run(function () {
    $pdo = pdo_pgsql_test_inc::create();
    // Preserve the original five-million-row fetchAll coverage without preparing a persistent table.
    $statement = $pdo->query("SELECT i AS id, 'data' || i AS data FROM generate_series(1, " . ROW_COUNT . ") AS i");
    $rows = $statement->fetchAll();
    Assert::same(count($rows), ROW_COUNT);
    $sum = 0;
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        if ($id < 1 || $id > ROW_COUNT || $row['data'] !== 'data' . $id
            || $row[0] !== $row['id'] || $row[1] !== $row['data']) {
            throw new RuntimeException('Invalid row in a large PostgreSQL result');
        }
        $sum += $id;
    }
    Assert::same($sum, intdiv(ROW_COUNT * (ROW_COUNT + 1), 2));
    echo "DONE\n";
});
?>
--EXPECT--
DONE
