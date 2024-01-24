--TEST--
swoole_pdo_sqlite: Bug #46542 Extending PDO class with a __call() function
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

class A extends PDO
{ function __call($m, $p) {print __CLASS__."::$m\n";} }

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $a = new A('sqlite:' . __DIR__ . '/dummy.db');

    $a->truc();
    $a->TRUC();
});
?>
--CLEAN--
<?php
unlink(__DIR__ . '/dummy.db');
?>
--EXPECT--
A::truc
A::TRUC
