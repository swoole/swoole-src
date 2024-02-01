--TEST--
swoole_pdo_sqlite: PDO SQLITE coroutine
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
use function Swoole\Coroutine\go;
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
$db = new PDO('sqlite:test.db');
$db->exec('create table if not exists test (id int)');
$db->exec('delete from test');

run(function() {
    for($i = 0; $i <= 20; $i++) {
        go(function() use ($i) {
            $db = new PDO('sqlite:test.db');
            $stmt = $db->prepare('insert into test values(?)');
            $stmt->execute([$i]);
            $stmt = $db->prepare('select id from test where id = ?');
            $stmt->execute([$i]);
            var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == $i);
        });
    }
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
