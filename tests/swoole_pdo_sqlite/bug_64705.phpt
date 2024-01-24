--TEST--
swoole_pdo_sqlite:__construct() fails
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $dsn = 'sqlite:./bug64705NonExistingDir/bug64705NonExistingDb';
    try {
        $pdo = new \PDO($dsn, null, null);
    } catch (\PDOException $e) {
        var_dump(!empty($e->errorInfo) && is_array($e->errorInfo));
    }
});
?>
--EXPECT--
bool(true)
