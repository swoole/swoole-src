--TEST--
test helpers: parallel fixtures cannot reserve the same port before binding
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$first = new Swoole\Process(static function ($process) {
    $process->write((string) find_free_port(static fn (int $candidate): bool => true));
    $process->read();
}, false, SOCK_DGRAM);
$first->start();
$firstPort = (int) $first->read();
$second = new Swoole\Process(static function ($process) use ($firstPort) {
    $process->write((string) find_free_port(static fn (int $candidate): bool => $candidate === $firstPort));
    $process->read();
}, false, SOCK_DGRAM);
$second->start();
$secondPort = (int) $second->read();
$first->write('release');
$second->write('release');
Swoole\Process::wait();
Swoole\Process::wait();
Assert::greaterThan($firstPort, 0);
Assert::same($secondPort, -1);
echo "DONE\n";
?>
--EXPECT--
DONE
