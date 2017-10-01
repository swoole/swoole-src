<?php
$table = new swoole_table(1024);
$table->column('id', swoole_table::TYPE_INT);
$table->column('name', swoole_table::TYPE_STRING, 64);
$table->column('num', swoole_table::TYPE_FLOAT);
$table->create();

$table['apple'] = array('id' => 145, 'name' => 'iPhone', 'num' => 3.1415);
$table['google'] = array('id' => 358, 'name' => "AlphaGo", 'num' => 3.1415);

$table['microsoft']['name'] = "Windows";
$table['microsoft']['num'] = '1997.03';

var_dump($table['apple']);
var_dump($table['microsoft']);

$table['google']['num'] = 500.90;
var_dump($table['google']);

