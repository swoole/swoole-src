--TEST--
swoole_pdo_sqlite: SQLite3 authorizer crashes on NULL values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--INI--
open_basedir=.
--FILE--
<?php
use function Swoole\Coroutine\run;
Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO("sqlite::memory:", null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    $db->exec('attach database \':memory:\' AS "db1"');
    var_dump($db->exec('create table db1.r (id int)'));

    try {
        $st = $db->prepare('attach database :a AS "db2"');
        $st->execute([':a' => ':memory:']);
        var_dump($db->exec('create table db2.r (id int)'));
    } catch (PDOException $ex) {
        echo $ex->getMessage(), PHP_EOL;
    }
});
?>
--EXPECT--
int(0)
SQLSTATE[HY000]: General error: 23 not authorized
