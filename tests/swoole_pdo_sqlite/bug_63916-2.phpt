--TEST--
swoole_pdo_sqlite:PARAM_INT casts to 32bit int internally even on 64bit builds in pdo_sqlite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
if (PHP_INT_SIZE > 4) die('skip 32-bit only');
?>
--FILE--
<?php
use function Swoole\Coroutine\run;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $num = PHP_INT_MAX; // 32 bits
    $conn = new PDO('sqlite::memory:');
    $conn->query('CREATE TABLE users (id INTEGER NOT NULL, num INTEGER NOT NULL, PRIMARY KEY(id))');

    $stmt = $conn->prepare('insert into users (id, num) values (:id, :num)');
    $stmt->bindValue(':id', 1, PDO::PARAM_INT);
    $stmt->bindValue(':num', $num, PDO::PARAM_INT);
    $stmt->execute();

    $stmt = $conn->query('SELECT num FROM users');
    $result = $stmt->fetchAll(PDO::FETCH_COLUMN);

    var_dump($num,$result[0]);
});
?>
--EXPECT--
int(2147483647)
int(2147483647)
