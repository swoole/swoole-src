--TEST--
swoole_pdo_sqlite:quote() may return unquoted string)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
if (PHP_INT_SIZE != 8) die("skip this test is for 64bit platforms only");
if (getenv("SKIP_SLOW_TESTS")) die("skip slow test");
?>
--INI--
memory_limit=-1
--FILE--
<?php
use function Swoole\Coroutine\run;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $pdo = new PDO("sqlite::memory:");
    $string = str_repeat("a", 0x80000000);
    var_dump($pdo->quote($string));
});
?>
--EXPECT--
bool(false)
