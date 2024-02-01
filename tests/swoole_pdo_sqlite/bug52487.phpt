--TEST--
swoole_pdo_sqlite:FETCH_INTO leaks memory)
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

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = PdoSqliteTest::create();
    $stmt = $db->prepare("select 1 as attr");
    for ($i = 0; $i < 10; $i++) {
        $stmt->setFetchMode(PDO::FETCH_INTO, new stdClass);
    }

    print "ok\n";
});
?>
--EXPECT--
ok
