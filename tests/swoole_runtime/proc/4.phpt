--TEST--
swoole_runtime/proc: proc_open() with no pipes
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

include_once dirname(__FILE__) . "/proc_open_pipes.inc";
Swoole\Runtime::enableCoroutine();

go(function() {

    $spec = array();

    $php = getenv("TEST_PHP_EXECUTABLE");
    $callee = create_sleep_script();
    proc_open("$php -n $callee", $spec, $pipes);

    var_dump(count($spec));
    var_dump($pipes);
});
swoole_event::wait();

?>
--CLEAN--
<?php
include_once dirname(__FILE__) . "/proc_open_pipes.inc";

unlink_sleep_script();

?>
--EXPECTF--
int(0)
array(0) {
}
