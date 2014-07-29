<?php
$table = new swoole_table(1024);
$table->column('id', swoole_table::TYPE_INT, 4);       //1,2,4,8
$table->column('name', swoole_table::TYPE_STRING, 64);
$table->column('num', swoole_table::TYPE_FLOAT, 4);     //4,8
$table->create();

$table->add('tianfenghan@qq.com', array('id' => 145, 'name' => 'rango', 'num' => 3.1415));
$table->add('350749960@qq.com', array('id' => 358, 'name' => str_repeat('A', 120), 'num' => 3.1415));
$table->add('hello@qq.com', array('id' => 189, 'name' => 'rango3', 'num' => 3.1415));

var_dump($table->get('350749960@qq.com'));
