<?php
$workers = array();
$worker_num = 4;

$table = new swoole_table(20000);
$table->column('fd', swoole_table::TYPE_INT);
$table->column('from_id', swoole_table::TYPE_INT);
$table->column('data', swoole_table::TYPE_STRING, 64);
$table->create();

function test()
{
    global $table;
    for ($i = 0; $i < 20000; $i++)
    {
        $key = 'user_' . $i;
        $ret = $table->set(
            $key,
            array(
                'fd'      => $i,
                'from_id' => rand(100, 999),
                'data'    => "hello_world_$i"
            )
        );
        if (!$ret)
        {
            echo "count $i failed.";
            break;
        }
    }
}

test();
exit;

function worker(swoole_process $process)
{

    return 0;
}

//for ($i = 0; $i < $worker_num; $i++)
//{
//    $process = new swoole_process('worker');
//    $process->start();
//    $workers[$i] = $process;
//}
//
//for ($i = 0; $i < $worker_num; $i++)
//{
//    $exit = swoole_process::wait();
//    echo "worker[$i] exit\n";
//}
