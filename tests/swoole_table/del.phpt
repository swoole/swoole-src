--TEST--
swoole_table: clear all columns
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(1024, 0.25);
$table->column('state', Swoole\Table::TYPE_INT);
$table->column('remainLen', Swoole\Table::TYPE_INT);
$table->column('data', Swoole\Table::TYPE_STRING, 64);
$table->create();

function data($table) {
    $table_key = 'table';
    $table->incr($table_key, 'state');
    $state = $table->get($table_key, 'state');
    var_dump($state);
    $data = $table->get($table_key, 'data');
    $data .= 'abc';
    $table->set($table_key, ['data' => $data]);
    var_dump($table->get($table_key));

    if ($state === 1) {
        $table->incr($table_key, 'remainLen', 3);
    } else {
        $remainLen = $table->get($table_key, 'remainLen');
        if ($remainLen === 3) {
            $res = $table->del($table_key);
            var_dump($res);
            var_dump($table->get($table_key));
        }
    }
}
data($table);
data($table);
data($table);
?>
--EXPECT--
int(1)
array(3) {
  ["state"]=>
  int(1)
  ["remainLen"]=>
  int(0)
  ["data"]=>
  string(3) "abc"
}
int(2)
array(3) {
  ["state"]=>
  int(2)
  ["remainLen"]=>
  int(3)
  ["data"]=>
  string(6) "abcabc"
}
bool(true)
bool(false)
int(1)
array(3) {
  ["state"]=>
  int(1)
  ["remainLen"]=>
  int(0)
  ["data"]=>
  string(3) "abc"
}
