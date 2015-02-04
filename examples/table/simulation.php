<?php
/**
 * The script is used for simulating the usage of swoole_table() and guaranting its usability.
 */
$table = new swoole_table(1024);
$table->column('name', swoole_table::TYPE_STRING, 64);
$table->column('id', swoole_table::TYPE_INT, 4);       //1,2,4,8
$table->column('num', swoole_table::TYPE_FLOAT);
$table->create();

while (true) {
    $i = rand(1, 1000);
    $if = rand(0,1);
    if ($if) {
        $table->set($i, ['id' => $i, 'name' => $i, 'num' => $i]);
    } else {
        $table->del($i);
    }
    var_dump('count ' . $table->count());
}
