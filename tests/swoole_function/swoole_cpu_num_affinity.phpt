--TEST--
swoole_cpu_num: Linux startup count respects CPU affinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip_if_no_process_affinity();
skip_if_function_not_exist('exec');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Process;
use SwooleTest\Assert;

Assert::setThrowException(true);
$original = Process::getAffinity();
Assert::notEmpty($original);
$startupCount = swoole_cpu_num();
$last = $original[array_key_last($original)];
$masks = [[$last]];
if (count($original) > 1) {
    $masks[] = [$original[0], $last];
}

$child = <<<'PHP'
$count = swoole_cpu_num();
$affinity = Swoole\Process::getAffinity();
if (!Swoole\Process::setAffinity(ORIGINAL_MASK)) {
    exit(1);
}
echo json_encode([$count, $affinity, swoole_cpu_num(), Swoole\Process::getAffinity()]);
PHP;
$child = str_replace('ORIGINAL_MASK', var_export($original, true), $child);
$command = escapeshellarg(PHP_BINARY) . ' ' . getenv('TEST_PHP_EXTRA_ARGS') . ' -r ' . escapeshellarg($child);

foreach ($masks as $mask) {
    Assert::true(Process::setAffinity($mask));
    try {
        Assert::same(swoole_cpu_num(), $startupCount);
        $output = [];
        exec($command, $output, $status);
        Assert::same($status, 0);
        $count = min(count($mask), $startupCount);
        Assert::same(json_decode(implode("\n", $output), true, 512, JSON_THROW_ON_ERROR), [$count, $mask, $count, $original]);
    } finally {
        Assert::true(Process::setAffinity($original));
    }
}

echo "DONE\n";
?>
--EXPECT--
DONE
