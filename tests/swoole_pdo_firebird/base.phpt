--TEST--
swoole_pdo_firebird: test hook pdo_firebird
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/pdo_firebird.inc';
PdoFirebirdTest::skip();
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/pdo_firebird.inc';

use function Swoole\Coroutine\run;

Co::set(['hook_flags' => SWOOLE_HOOK_PDO_FIREBIRD]);
run(static function (): void {
    $db = PdoFirebirdTest::create();

    $db->exec('CREATE TABLE test_table (id INTEGER PRIMARY KEY, name VARCHAR(50))');

    $db->exec("INSERT INTO test_table VALUES (1, 'Firebird Test')");

    $stmt = $db->query('SELECT * FROM test_table');
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    $stmt = null;
    var_dump($result);

    $db->exec('DROP TABLE test_table');
});
echo "DONE\n";
?>
--EXPECTF--
array(2) {
  ["ID"]=>
  int(1)
  ["NAME"]=>
  string(13) "Firebird Test"
}
DONE
