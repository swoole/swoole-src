--TEST--
swoole_pdo_sqlite: Testing transaction
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO('sqlite::memory:');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);

    $db->beginTransaction();

    $db->query('CREATE TABLE IF NOT EXISTS foobar (id INT AUTO INCREMENT, name TEXT)');
    $db->commit();

    $db->beginTransaction();
    $db->query('INSERT INTO foobar VALUES (NULL, "PHP")');
    $db->query('INSERT INTO foobar VALUES (NULL, "PHP6")');
    $db->rollback();

    $r = $db->query('SELECT COUNT(*) FROM foobar');
    var_dump($r->rowCount());


    $db->query('DROP TABLE foobar');
});
?>
--EXPECTF--
int(0)

Warning: PDO::query(): SQLSTATE[HY000]: General error: 6 database table is locked in %s on line %d
