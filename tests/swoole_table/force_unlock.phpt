--TEST--
swoole_table: rows remain readable after a child runs out of PHP memory
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$table = new \Swoole\Table(1);
$table->column('string', \Swoole\Table::TYPE_STRING, 4 * 1024 * 1024);
$table->column('int', \Swoole\Table::TYPE_INT, 8);
$table->create();
$str_size = 4 * 1024 * 1024;
$str_value = random_bytes($str_size);
$data = [
    'string' => $str_value,
    'int' => PHP_INT_MAX
];
$table->set('test', $data);

$proc = new Process(function () use ($table) {
    // Leave less than one column's allocation available, regardless of the
    // PHP build's baseline usage. The OOM must happen in get(), not setup.
    ini_set('memory_limit', (string) (memory_get_usage(true) + 2 * 1024 * 1024));
    $data = $table->get('test');
    var_dump(strlen($data['string']));
    var_dump(memory_get_usage());
}, true, SOCK_STREAM);

$proc->start();

$exit_status = Process::wait();
Assert::eq($exit_status['code'], 255);
Assert::contains($proc->read(), 'Fatal error: Allowed memory');

// The OOM path does not always leave a held row lock across PHP builds. Assert
// data recovery here; core test table.lock_crash covers an abandoned lock directly.
$data = $table->get('test');
Assert::eq(strlen($data['string']), $str_size);
Assert::eq($data['string'], $str_value);
echo "Done\n";
?>
--EXPECTREGEX--
(?:\[[^\r\n]+\]\tWARNING\tTableRow::lock\(\): lock process\[\d+\] not exists, force unlock\r?\n)?Done
