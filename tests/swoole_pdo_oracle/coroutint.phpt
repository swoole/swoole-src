--TEST--
swoole_pdo_oracle: PDO OCI coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';

Co::set(['hook_flags'=> SWOOLE_HOOK_ALL]);
run(function() {
    $db = PdoOracleTest::create();
    $db->exec("create table test (id int)");
    for($i = 0; $i < 10; $i++) {
        go(function () use($db, $i){
            $stmt = $db->prepare("insert into test values (?)");
            $stmt->execute([$i]);
            $stmt = $db->prepare("select id from test where id = ?");
            $stmt->execute([$i]);
            var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == $i);
        });
    }
    sleep(1);
    $db->exec("drop table test");
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
