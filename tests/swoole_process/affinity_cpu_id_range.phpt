--TEST--
swoole_process: reject CPU IDs outside the available CPU range
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$original = Process::getAffinity();
$cpu = $original[0];

try {
    Assert::true(Process::setAffinity([$cpu]));

    $warning = null;
    set_error_handler(function ($errno, $message) use (&$warning) {
        $warning = $message;
        return true;
    });
    try {
        // Linux silently intersects affinity masks with the CPUs that are
        // physically present. Reject the invalid member before that happens.
        Assert::false(Process::setAffinity([$cpu, swoole_cpu_num()]));
    } finally {
        restore_error_handler();
    }

    Assert::contains($warning, 'invalid cpu id [' . swoole_cpu_num() . ']');
    Assert::same(Process::getAffinity(), [$cpu]);
} finally {
    @Process::setAffinity($original);
}
?>
--EXPECT--
