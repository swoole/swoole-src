--TEST--
swoole_table: get after destroy
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Table;

$table = new Table(1024);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 10);
$table->create();

$table->set('1', ['id' => 1, 'name' => 'rango']);

Assert::eq($table->get('1')['id'], 1);
Assert::eq($table->get('1')['name'], 'rango');

$proc = new Process(function () use ($table) {
    usleep(10000);
    Assert::eq($table->get('1')['id'], 2);
    Assert::eq($table->get('1')['name'], '');
}, true, SOCK_STREAM);

$proc->start();

$table->destroy();

$output = $proc->read();
Assert::contains($output, 'table is not created or has been destroyed');
$retval = Process::wait();
Assert::eq($retval['code'], 255);
?>
--EXPECT--
