--TEST--
PDO_OCI: phpinfo() output
--SKIPIF--
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
    ob_start();
    phpinfo();
    $tmp = ob_get_contents();
    ob_end_clean();

    $reg = 'PDO Driver for OCI 8 and later => enabled';
    if (!preg_match("/$reg/", $tmp)) {
        printf("[001] Cannot find OCI PDO driver line in phpinfo() output\n");
    }

    print "done!";
});
?>
--EXPECT--
done!
