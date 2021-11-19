<?php
$table = new Swoole\Table(1024);
$table->column('name', Swoole\Table::TYPE_STRING, 64);
$table->column('id', Swoole\Table::TYPE_INT, 4);       //1,2,4,8
$table->column('num', Swoole\Table::TYPE_FLOAT);
$table->create();

$table->set('tianfenghan@qq.com', array('id' => 145, 'name' => 'rango1', 'num' => 3.1415));
$table->set('350749960@qq.com', array('id' => 358, 'name' => "Rango2", 'num' => 3.1415));
$table->set('hello@qq.com', array('id' => 189, 'name' => 'rango3', 'num' => 3.1415));

var_dump($table->get('350749960@qq.com'));
var_dump($table->get('350749960@qq.com', 'name'));

foreach($table as $key => $value)
{
    var_dump($key, $value);
}

echo "======================= Total Elements: {$table->count()} ============================\n";
$table->del('350749960@qq.com'); // delete a exist element
foreach($table as $key => $value)
{
    var_dump($key, $value);
}
echo "======================= Total Elements: {$table->count()} ============================\n";
$ret = $table->del('a invalid key'); // delete a invalid element
var_dump($ret);
foreach($table as $key => $value)
{
    var_dump($key, $value);
}
echo "======================= Total Elements: {$table->count()} ============================\n";
