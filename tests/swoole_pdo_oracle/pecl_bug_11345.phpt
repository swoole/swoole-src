--TEST--
swoole_pdo_oracle: PECL PDO_OCI Bug #11345 (Test invalid character set name)
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

// This tests only part of PECL bug 11345.  The other part - testing
// when the National Language Support (NLS) environment can't be
// initialized - is very difficult to test portably.

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_ORACLE]);
run(function() {
    try {
        $dbh = new PDO('oci:dbname=xxx;charset=yyy', 'abc', 'def');
    }
    catch (PDOException $e) {
        echo 'Connection failed: ' . $e->getMessage(). "\n";
    }
});
?>
--EXPECTF--
Connection failed: SQLSTATE[HY000]: OCINlsCharSetNameToId: unknown character set name (%s)
