--TEST--
swoole_pdo_oracle: PDO OCI transcation1
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
    $db->exec('create table transcation1 (id int)');
    go(function () use($db){
        $db->beginTransaction();
        $stmt = $db->prepare("insert into transcation1 values (?)");
        $stmt->execute([1]);
        go(function () use($db){
            $db->beginTransaction();
            $stmt = $db->prepare("insert into transcation1 values (?)");
            $stmt->execute([2]);
            $db->rollback();
        });
        sleep(2);
        $db->commit();
        $stmt = $db->prepare("select id from transcation1 where id = ?");
        $stmt->execute([1]);
        var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == 1);
    });
    sleep(4);
});
?>
--EXPECTF--
Fatal error: Uncaught PDOException: There is already an active transaction in %s:%d
Stack trace:
#0 %s(%d): PDO->beginTransaction()
%A
  thrown in %s on line %d
