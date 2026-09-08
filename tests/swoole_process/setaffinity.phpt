--TEST--
swoole_process: setAffinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
$cpus = Swoole\Process::getAffinity();
$cpus = array_filter($cpus, fn ($cpu) => $cpu < swoole_cpu_num());
skip('no usable cpu id', !$cpus);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$original = Swoole\Process::getAffinity();
$cpus = array_values(array_filter($original, fn ($cpu) => $cpu < swoole_cpu_num()));
$cpu = $cpus[0];

try {
    Assert::true(Swoole\Process::setAffinity([(string) $cpu]));
    Assert::same(Swoole\Process::getAffinity(), [$cpu]);

    if (count($cpus) > 1) {
        Assert::true(Swoole\Process::setAffinity([$cpus[0], $cpus[1]]));
        Assert::same(Swoole\Process::getAffinity(), [$cpus[0], $cpus[1]]);
    }

    $warning = null;
    set_error_handler(function ($errno, $message) use (&$warning) {
        $warning = $message;
        return true;
    });
    try {
        Assert::false(Swoole\Process::setAffinity([$cpu, -1]));
    } finally {
        restore_error_handler();
    }
    Assert::contains($warning, 'invalid cpu id [-1]');
} finally {
    @Swoole\Process::setAffinity($original);
}
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
