<?php

class UnitTest_Table
{
    static $workers = array();
    //并发进程数
    static $worker_num = 8;
    //生成10万个key
    static $key_base = 100001;
    static $key_num = 100000;
    //每个进程运行20万次
    static $worker_test_count = 2000000;

    /**
     * @var swoole_table
     */
    static $table;

    static function run()
    {
        $table = new swoole_table(1024 * 256);
        $table->column('index', swoole_table::TYPE_INT);
        $table->column('serid', swoole_table::TYPE_INT);
        $table->column('data', swoole_table::TYPE_STRING, 64);
        $table->create();

        self::$table = $table;

        for ($i = 0; $i < self::$key_num; $i++)
        {
            $key = 'user_' . (self::$key_base + $i);
            $ret = self::$table->set(
                $key,
                array(
                    'index' => $i,
                    'serid' => rand(1000, 9999),
                    'data' => "hello_world_$i"
                )
            );
            if (!$ret)
            {
                echo "count $i failed.";
                break;
            }
        }

        for ($i = 0; $i < self::$worker_num; $i++) {
            $process = new swoole_process('UnitTest_Table::worker');
            $process->start();
            $workers[$i] = $process;
        }

        for ($i = 0; $i < self::$worker_num; $i++)
        {
            $exit = swoole_process::wait();
            echo "worker[$i] exit\n";
        }
    }

    static function worker(swoole_process $process)
    {
        for ($i = 0; $i < self::$worker_test_count; $i++)
        {
            $index = rand(0, self::$key_num - 1);
            $key = 'user_' . (self::$key_base + $index);

            //set还是get操作
            $execute_set = rand(0, 1) == 0 ? true : false;

            if ($execute_set)
            {
                $ret = self::$table->set(
                    $key,
                    array(
                        //'index' => $index,
                        'serid' => rand(1000, 9999),
                        'data' => "hello_world_$i"
                    )
                );
                if (!$ret)
                {
                    echo "set $key failed.\n";
                    break;
                }
            }
            else
            {
                $ret = self::$table->get($key);
                if (!is_array($ret))
                {
                    echo "get $key failed.\n";
                    break;
                }
                elseif ($ret['index'] != $index)
                {
                    echo "index invalid\n";
                    var_dump($ret, $index);
                }
            }
        }
        return 0;
    }
}

UnitTest_Table::run();
