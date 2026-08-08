--TEST--
swoole_table: constructor and count parse before native state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

// These re-entry vectors are PHP 8 scalar-coercion diagnostics; PHP 9 promotes them to TypeError.
$table = new Table(8);
$table->column('id', Table::TYPE_INT);
$table->create();
$table->set('row', ['id' => 1]);
Assert::same($table->count(), 1);

$destroyed = false;
set_error_handler(function () use ($table, &$destroyed): bool {
    $destroyed = true;
    $table->destroy();

    return true;
});
try {
    Assert::same($table->count(8.5), 0);
} finally {
    restore_error_handler();
}
Assert::true($destroyed);

$table     = (new ReflectionClass(Table::class))->newInstanceWithoutConstructor();
$reentered = false;
set_error_handler(function () use ($table, &$reentered): bool {
    $reentered = true;
    $table->__construct(8);
    $table->column('id', Table::TYPE_INT);
    $table->create();
    $table->set('row', ['id' => 1]);

    return true;
});
try {
    try {
        $table->__construct(8.5);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Table can only be called once');
    }
} finally {
    restore_error_handler();
}
Assert::true($reentered);
Assert::same($table->get('row'), ['id' => 1]);
Assert::same($table->count(), 1);
?>
--EXPECT--
