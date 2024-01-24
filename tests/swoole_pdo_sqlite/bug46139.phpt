--TEST--
swoole_pdo_sqlite: Bug #46139 (PDOStatement->setFetchMode() forgets FETCH_PROPS_LATE)
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
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';

class Person {
    public $test = NULL;
    public function __construct() {
        var_dump($this->test);
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = PdoSqliteTest::create();

    $stmt = $db->query("SELECT 'foo' test, 1");
    $stmt->setFetchMode(PDO::FETCH_CLASS | PDO::FETCH_PROPS_LATE, 'Person');
    $r1 = $stmt->fetch();
    printf("'%s'\n", $r1->test);

    $stmt = $db->query("SELECT 'foo' test, 1");
    $stmt->setFetchMode(PDO::FETCH_CLASS | PDO::FETCH_PROPS_LATE, 'Person');
    $r1 = $stmt->fetchAll();
    printf("'%s'\n", $r1[0]->test);

    $stmt = $db->query("SELECT 'foo' test, 1");
    $stmt->setFetchMode(PDO::FETCH_CLASS | PDO::FETCH_PROPS_LATE, 'Person');
    $r1 = $stmt->fetch(PDO::FETCH_CLASS | PDO::FETCH_PROPS_LATE);
    printf("'%s'\n", $r1->test);
});
?>
--EXPECT--
NULL
'foo'
NULL
'foo'
NULL
'foo'
