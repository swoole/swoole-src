--TEST--
swoole_server: cpu_affinity_ignore rejects all available CPUs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;

$cpu = Process::getAffinity()[0];
Assert::true(Process::setAffinity([$cpu]));

$server = new Server('127.0.0.1', 0);
try {
$server->set([
    'cpu_affinity_ignore' => [$cpu],
]);
    Assert::true(false, 'invalid affinity settings must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getMessage(), 'cpu_affinity_ignore excludes all available CPUs');
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
}
echo "DONE\n";
?>
--EXPECT--
DONE
