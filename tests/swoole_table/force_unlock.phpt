--TEST--
swoole_table: force unlock
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

ini_set('memory_limit', '16M');

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
    $str = str_repeat('A', 5 * 1024 * 1024);
    // Fatal error: memory exhausted
    $data = $table->get('test');
    var_dump(strlen($data['string']));
    var_dump(strlen($str));
    var_dump(memory_get_usage());
}, true, SOCK_STREAM);

$proc->start();

$exit_status = Process::wait();
Assert::eq($exit_status['code'], 255);
Assert::contains($proc->read(), 'Fatal error: Allowed memory');

$data = $table->get('test');
Assert::eq(strlen($data['string']), $str_size);
Assert::eq($data['string'], $str_value);
echo "Done\n";
?>
--EXPECTF--
[%s]	WARNING	TableRow::lock(): lock process[%d] not exists, force unlock
Done
