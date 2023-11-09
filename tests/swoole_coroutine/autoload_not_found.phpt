--TEST--
swoole_coroutine: autoload not in coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

spl_autoload_register(function ($class) {
    if ($class == 'SwooleTestClassA2') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/A2.php';
    }
});

Co\run( function() {
    var_dump(new SwooleTestClassA2());
});
?>
--EXPECTF--
Fatal error: Uncaught Error: Class "SwooleTestClassA2" not found in %s:%d
Stack trace:
#0 %s(%d): %s
#1 %s(%d): %s
#2 [internal function]: {closure}()
#3 {main}
  thrown in %s on line %d
