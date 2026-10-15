--TEST--
swoole_thread/server: dispatch_func requires PROCESS mode
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Assert::setThrowException(true);
foreach ([SWOOLE_BASE, SWOOLE_THREAD] as $mode) {
    $server = new Swoole\Server('127.0.0.1', 0, $mode);
    try {
        $server->set(['dispatch_func' => fn () => 0]);
        Assert::true(false, 'unsupported callback must throw');
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::same($exception->getMessage(), 'dispatch_func is only supported in PROCESS mode');
    }
    Assert::null($server->setting);
    unset($server);
}
if (defined('SWOOLE_PROCESS')) {
    $server = new Swoole\Server('127.0.0.1', 0, SWOOLE_PROCESS);
    Assert::true($server->set(['dispatch_func' => fn () => 0]));
}
echo "DONE\n";
?>
--EXPECT--
DONE
