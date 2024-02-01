--TEST--
swoole_pdo_oracle: phpinfo() output
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
    ob_start();
    phpinfo();
    $tmp = ob_get_contents();
    ob_end_clean();

    $reg = 'coroutine_oracle => enabled';
    if (!preg_match("/$reg/", $tmp)) {
        printf("[001] Cannot find OCI PDO driver line in phpinfo() output\n");
    }

    print "done!";
});
?>
--EXPECT--
done!
