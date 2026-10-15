--TEST--
swoole_server_port: invalid settings throw consistently and allow a valid retry
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
Assert::true($server->set(['worker_num' => 1, 'log_file' => '/dev/null']));
$warnings = 0;
set_error_handler(function ($severity) use (&$warnings) {
    Assert::same($severity, E_WARNING);
    $warnings++;
    return true;
});
try {
    foreach ([$server->ports[0], $server] as $target) {
        $settings = $target->setting;
        try {
            $target->set(['package_length_func' => 'swoole_test_missing_length_function']);
            Assert::true(false, 'invalid callback must throw');
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        }
        Assert::same($target->setting, $settings);
    }
    $settings = $server->setting;
    foreach ([['dispatch_func' => 'swoole_test_missing_dispatch_function'], ['upload_max_filesize' => -1],
        ['name_resolver' => true]] as $options) {
        try {
            $server->set($options);
            Assert::true(false, 'invalid settings must throw');
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        }
    }
    Assert::same($server->setting, $settings);
} finally {
    restore_error_handler();
}
Assert::same($warnings, 0);
Assert::true($server->set(['worker_num' => 1]));
echo "DONE\n";
?>
--EXPECT--
DONE
