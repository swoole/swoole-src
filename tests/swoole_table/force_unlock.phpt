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

(new Process(function () use ($table) {
    $str = str_repeat('A', 4 * 1024 * 1024);
    // Fatal error: memory exhausted
    $data = $table->get('test');
    var_dump(strlen($data['string']));
    var_dump(strlen($str));
    var_dump(memory_get_usage());
}))->start();

Process::wait();

$data = $table->get('test');
Assert::eq(strlen($data['string']), $str_size);
Assert::eq($data['string'], $str_value);
echo "Done\n";
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted at %s (tried to allocate %d bytes) in %s on line %d
[%s]	WARNING	lock: lock process[%d] not exists, force unlock
Done
