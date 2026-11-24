--TEST--
swoole_thread: ArrayList preserves its contents when index conversion throws
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$list = new Swoole\Thread\ArrayList(['first', 'second']);
set_error_handler(static function ($severity, $message) {
    throw new ErrorException($message, 0, $severity);
});
try {
    $list->offsetSet(new stdClass, 'overwritten');
    Assert::true(false, 'Index conversion must propagate the error handler exception');
} catch (ErrorException $exception) {
    Assert::same($exception->getSeverity(), E_WARNING);
} finally {
    restore_error_handler();
}
Assert::same($list->toArray(), ['first', 'second']);
$list->offsetSet('1', 'updated');
$list[] = 'third';
Assert::same($list->toArray(), ['first', 'updated', 'third']);
echo "DONE\n";
?>
--EXPECT--
DONE
