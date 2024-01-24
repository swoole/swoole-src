--TEST--
swoole_pdo_sqlite:debugDumpParams() with bound params
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

    $x= $db->prepare('select :a, :b, ?');
    $x->bindValue(':a', 1, PDO::PARAM_INT);
    $x->bindValue(':b', 'foo');
    $x->bindValue(3, 1313);
    var_dump($x->debugDumpParams());
});
?>
--EXPECT--
SQL: [16] select :a, :b, ?
Params:  3
Key: Name: [2] :a
paramno=-1
name=[2] ":a"
is_param=1
param_type=1
Key: Name: [2] :b
paramno=-1
name=[2] ":b"
is_param=1
param_type=2
Key: Position #2:
paramno=2
name=[0] ""
is_param=1
param_type=2
NULL
