<?php
/**
 * The script is used for simulating the usage of Swoole\Table() and guarantying its usability.
 */
$table = new Swoole\Table(1024);
$table->column('name', Swoole\Table::TYPE_STRING, 64);
$table->column('id', Swoole\Table::TYPE_INT, 4);       //1,2,4,8
$table->column('num', Swoole\Table::TYPE_FLOAT);
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
