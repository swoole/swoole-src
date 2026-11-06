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
    try {
        $db->exec("drop table swoole_oci_coroutine");
    } catch (PDOException $e) {
        if ((int) $e->errorInfo[1] !== 942) {
            throw $e;
        }
    }
    $db->exec("create table swoole_oci_coroutine (id int)");
    $coroutines = [];
    for($i = 0; $i < 10; $i++) {
        $coroutines[] = go(function () use($db, $i){
            $stmt = $db->prepare("insert into swoole_oci_coroutine values (?)");
            $stmt->execute([$i]);
            $stmt = $db->prepare("select id from swoole_oci_coroutine where id = ?");
            $stmt->execute([$i]);
            var_dump($stmt->fetch(PDO::FETCH_ASSOC)['id'] == $i);
        });
    }
    Assert::true(Co::join($coroutines, 10));
    $db->exec("drop table swoole_oci_coroutine");
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
