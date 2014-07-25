<?php
$table = new swoole_table(1000);  //table rows size
$table->column('id', swoole_table::TYPE_INT, 4);       //1,2,4,8
$table->column('name', swoole_table::TYPE_STRING, 64);
$table->column('num', swoole_table::TYPE_FLOAT, 4);     //4,8
$table->create();

exit;

//memory size= 72 * (100000 + 20000) //20% conflict
$key = 'tianfenghan@qq.com';
$table->add($key, array('id' => 145, 'name' => 'rango', 'num' => 3.1415));
$value = $table->get($key);
$table->set($key, array('id' => 120, 'num' => 1.414));
$table->del($key);

$rows = $table->find(array('id' => 10), swoole_table::FIND_GT);
$rows = $table->find(array('id' => 10), swoole_table::FIND_LT);
$rows = $table->find(array('id' => 10), swoole_table::FIND_EQ); //default
$rows = $table->find(array('id' => 10), swoole_table::FIND_NEQ);
$rows = $table->find(array('name' => 'ran'), swoole_table::FIND_LEFTLIKE);
$rows = $table->find(array('name' => 'go'), swoole_table::FIND_RIGHTLIKE);

while($row = $table->next())
{
    var_dump($row);
}
