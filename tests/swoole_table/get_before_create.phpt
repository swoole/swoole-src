--TEST--
swoole_table: get before create
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Table;

$proc = new Process(function ()  {
    $table = new Table(1024);
    $table->column('id', Table::TYPE_INT);
    $table->column('name', Table::TYPE_STRING, 10);

    Assert::eq($table->get('1')['id'], 1);
    Assert::eq($table->get('1')['name'], 'rango');
}, true, SOCK_STREAM);

$proc->start();

$output = $proc->read();
Assert::contains($output, 'table is not created or has been destroyed');
$retval = Process::wait();
Assert::eq($retval['code'], 255);
?>
--EXPECT--
