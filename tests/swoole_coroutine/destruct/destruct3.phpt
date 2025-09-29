--TEST--
swoole_coroutine/destruct: destruct 3
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; skip_if_php_version_lower_than('8.1'); ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine as co;

$t = new class() {
    function __construct()
    {

    }

    function test()
    {
        echo "test\n";
    }

    function dtor()
    {
        echo "dtor\n";
        go(function () {
            throw new Exception('error');
        });
    }

    function __destruct()
    {
        $this->dtor();
    }
};

Co\go(function () use ($t) {
    Co::sleep(0.01);
    $t->test();
    $GLOBALS['obj'] = $t;
});
Swoole\Event::wait();
?>
--EXPECTF--
test
dtor

Fatal error: Uncaught Exception: error in %s:%d
Stack trace:
#0 [internal function]: class@anonymous->{closure%S()
#1 {main}
  thrown in %s on line %d
