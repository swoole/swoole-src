--TEST--
swoole_pdo_sqlite: PDO SQLite open_basedir check
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80100) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.1 or higher');
}

require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--INI--
open_basedir=.
--FILE--
<?php
use function Swoole\Coroutine\run;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    chdir(__DIR__);

    try {
        $db = new PDO('sqlite:../not_in_open_basedir.sqlite');
    } catch (Exception $e) {
        echo $e->getMessage() . "\n";
    }
    try {
        $db = new PDO('sqlite:file:../not_in_open_basedir.sqlite');
    } catch (Exception $e) {
        echo $e->getMessage() . "\n";
    }
    try {
        $db = new PDO('sqlite:file:../not_in_open_basedir.sqlite?mode=ro');
    } catch (Exception $e) {
        echo $e->getMessage() . "\n";
    }
});
?>
--EXPECT--
open_basedir prohibits opening ../not_in_open_basedir.sqlite
open_basedir prohibits opening file:../not_in_open_basedir.sqlite
open_basedir prohibits opening file:../not_in_open_basedir.sqlite?mode=ro
