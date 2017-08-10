<?php
$table = new swoole_table(1 << 18);
$table->column('id', swoole_table::TYPE_INT, 4);       //1,2,4,8
$table->column('name', swoole_table::TYPE_STRING, 17623);
$table->column('num', swoole_table::TYPE_FLOAT);
$table->create();

define('N', 100000);

//$worker = new swoole_process('child1', false, false);
//$worker->start();
//
//child
function child1($worker)
{
    global $table;
    $s = microtime(true);
    for($i =0; $i < N; $i++)
    {
        $table->set('tianfenghan@qq.com', array('id' => 145, 'name' => 'rango', 'num' => 3.1415));
        $table->set('350749960@qq.com', array('id' => 358, 'name' => "Rango1234", 'num' => 3.1415));
        $table->set('hello@qq.com', array('id' => 189, 'name' => 'rango3', 'num' => 3.1415));
        $table->set('tianfenghan@chelun.com', array('id' => 145, 'name' => 'rango', 'num' => 3.1415));
        $table->set('12811247@qq.com', array('id' => 1358, 'name' => "Swoole", 'num' => 3.1415));
    }
    echo "set - ".(5*N)." use: ".round((microtime(true) - $s) * 1000, 4)."ms\n";
}

//master
sleep(1);

child1(1245);
$s = microtime(true);
for($i =0; $i < N; $i++)
{
    $arr1 = $table->get('tianfenghan@qq.com');
    $arr2 = $table->get('350749960@qq.com');
    $arr3 = $table->get('hello@qq.com');
    $arr4 = $table->get('tianfenghan@chelun.com');
    $arr5 = $table->get('12811247@qq.com');
}

echo "get - ".(5*N)." use: ".round((microtime(true) - $s) * 1000, 4)."ms\n";
$s = microtime(true);

var_dump($arr1, $arr2, $arr3, $arr4, $arr5);
