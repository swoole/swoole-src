--TEST--
swoole_pdo_sqlite: Testing sqliteCreateFunction() with flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
if (!defined('PDO::SQLITE_DETERMINISTIC')) die('skip system sqlite is too old');
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO('sqlite::memory:');

    $db->query('CREATE TABLE IF NOT EXISTS foobar (id INT AUTO INCREMENT, name TEXT)');

    $db->query('INSERT INTO foobar VALUES (NULL, "PHP")');
    $db->query('INSERT INTO foobar VALUES (NULL, "PHP6")');


    $db->sqliteCreateFunction('testing', function($v) { return strtolower($v); }, 1, PDO::SQLITE_DETERMINISTIC);


    foreach ($db->query('SELECT testing(name) FROM foobar') as $row) {
        var_dump($row);
    }

    $db->query('DROP TABLE foobar');
});
?>
--EXPECT--
array(2) {
  ["testing(name)"]=>
  string(3) "php"
  [0]=>
  string(3) "php"
}
array(2) {
  ["testing(name)"]=>
  string(4) "php6"
  [0]=>
  string(4) "php6"
}
