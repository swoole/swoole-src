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
    if ($class == 'SwooleTestClassA') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/A.php';
    }
});

var_dump(new SwooleTestClassA());
var_dump(new SwooleTestClassA());

?>
--EXPECTF--
object(SwooleTestClassA)#%d (0) {
}
object(SwooleTestClassA)#%d (0) {
}
