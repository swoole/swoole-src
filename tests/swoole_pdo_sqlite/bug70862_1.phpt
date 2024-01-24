--TEST--
swoole_pdo_sqlite: Testing sqliteCreateCollation()
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80200) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.2 or higher');
}
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO('sqlite::memory:');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $db->exec('CREATE TABLE test(field BLOB)');

    $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, 0);
    $db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, true);

    class HelloWrapper {
        public function stream_open() { return true; }
        public function stream_eof() { return true; }
        public function stream_read() { return NULL; }
        public function stream_stat() { return array(); }
    }
    stream_wrapper_register("hello", "HelloWrapper");

    $f = fopen("hello://there", "r");

    $stmt = $db->prepare('INSERT INTO test(field) VALUES (:para)');
    $stmt->bindParam(":para", $f, PDO::PARAM_LOB);
    $stmt->execute();

    var_dump($f);
});
?>
+++DONE+++
--EXPECTF--

Deprecated: Creation of dynamic property HelloWrapper::$context is deprecated in %s on line %d
string(0) ""
+++DONE+++
