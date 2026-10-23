--TEST--
swoole_pdo_oracle:ATTR_STRINGIFY_FETCHES and blob)
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

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_ORACLE]);
run(function() {
    $db = PdoOracleTest::create();
    $table = PdoOracleTest::tableName('pdo_blob');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, true);

    $db->beginTransaction();

    $db->query("CREATE TABLE {$table} (id INT NOT NULL, blob1 BLOB)");

    try {
        $stmt = $db->prepare("INSERT INTO {$table} (id, blob1) VALUES (:id, EMPTY_BLOB()) RETURNING blob1 INTO :foo");

        $data = 'foo';
        $blob = fopen('php://memory', 'a');
        fwrite($blob, $data);
        rewind($blob);

        $id = 1;
        $stmt->bindparam(':id', $id);
        $stmt->bindparam(':foo', $blob, PDO::PARAM_LOB);
        $stmt->execute();
        // PHP 8.4.27 also closes the cursor automatically before re-execution.
        Assert::true($stmt->closeCursor());

        $data = '';
        $blob = fopen('php://memory', 'a');
        fwrite($blob, $data);
        rewind($blob);

        $id = 1;
        $stmt->bindparam(':id', $id);
        $stmt->bindparam(':foo', $blob, PDO::PARAM_LOB);
        $stmt->execute();

        $res = $db->query("SELECT blob1 from {$table}");
        // Resource
        var_dump($res->fetch());

        // Empty string
        var_dump($res->fetch());

    } finally {
        $res = null;
        $stmt = null;
        $db->exec("DROP TABLE {$table}");
    }
});
?>
--EXPECT--
array(2) {
  ["blob1"]=>
  string(3) "foo"
  [0]=>
  string(3) "foo"
}
array(2) {
  ["blob1"]=>
  string(0) ""
  [0]=>
  string(0) ""
}
