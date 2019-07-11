--TEST--
swoole_table: row
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$table = new swoole_table(1);
$table->column('bar', swoole_table::TYPE_STRING, 255);
$table->create();
$table->set('rpw', ['bar' => 'hello world']);
$row = $table['rpw'];
@$row['not_exist'] = '666';
Assert::true(!isset($row['not_exist']));
echo $row['bar'] . "\n";
$row['bar'] = 'hello swoole';
echo $row['bar'] . "\n";
$row['bar'] = null;
echo $row['bar'] . "EOF\n";
Assert::true(isset($row['bar']));
?>
--EXPECT--
hello world
hello swoole
EOF
