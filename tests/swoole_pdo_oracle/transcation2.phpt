--TEST--
swoole_pdo_oracle: PDO OCI transcation2
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
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';

Co::set(['hook_flags'=> SWOOLE_HOOK_ALL]);
run(function() {
    $db = PdoOracleTest::create();
    $db->exec('create table transcation2 (id int)');

    go(function() {
        $db = PdoOracleTest::create();
        $db->beginTransaction();
        $stmt = $db->prepare("insert into transcation2 values (?)");
        $stmt->execute([1]);
        $db->commit();
        $stmt = $db->prepare("select id from transcation2 where id = ?");
        $stmt->execute([1]);
        var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == 1);
    });

    go(function(){
        $db = PdoOracleTest::create();
        $db->beginTransaction();
        $stmt = $db->prepare("insert into transcation2 values (?)");
        $stmt->execute([2]);
        $db->commit();
        $stmt = $db->prepare("select id from transcation2 where id = ?");
        $stmt->execute([2]);
        var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == 2);
    });
    sleep(1);
    $db->exec('drop table transcation2');
});
?>
--EXPECT--
bool(true)
bool(true)
