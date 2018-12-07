<?php
$table = new swoole_table(8 * 1024 * 1024);
$table->column('id', swoole_table::TYPE_INT, 4);
$table->column('name', swoole_table::TYPE_STRING, 32);
$table->column('num', swoole_table::TYPE_FLOAT);
$table->create();

define('N', 1000000);
define('C', 4);

test1();
test2();
test3();
test4();


function test1()
{
    global $table;

    /**
     * table_size = 1M
     */
    $s = microtime(true);
    $n = N;
    while ($n--) {
        $table->set('key_' . $n, array('id' => $n, 'name' => "swoole, value=$n\r\n", 'num' => 3.1415 * rand(10000, 99999)));
    }
    echo "set " . N . " keys, use: " . round((microtime(true) - $s) * 1000, 2) . "ms\n";
}

function test2()
{
    global $table;
    $n = N;
    $s = microtime(true);
    while ($n--) {
        $key = rand(0, N);
        $data = $table->get('key_' . $key);
    }
    echo "get " . N . " keys, use: " . round((microtime(true) - $s) * 1000, 2) . "ms\n";
}

function test3()
{
    for ($i = C; $i--;) {
        (new swoole_process(function () use ($i) {
            global $table;
            $n = N;
            $s = microtime(true);
            while ($n--) {
                $key = rand(0, N);
                $data = $table->get('key_' . $key);
            }
            echo "[Worker#$i]get " . N . " keys, use: " . round((microtime(true) - $s) * 1000, 2) . "ms\n";
        }))->start();
    }
    for ($i = C; $i--;) {
        swoole_process::wait();
    }
}

function test4()
{
    for ($i = C; $i--;) {
        (new swoole_process(function () use ($i) {
            global $table;
            $n = N;
            $s = microtime(true);
            while ($n--) {
                $key = rand(0, N);
                $table->set('key_' . $key, array('id' => $key, 'name' => "php, value=$n\r\n", 'num' => 3.1415 * rand(10000, 99999)));
            }
            echo "[Worker#$i]set " . N . " keys, use: " . round((microtime(true) - $s) * 1000, 2) . "ms\n";
        }))->start();
    }
    for ($i = C; $i--;) {
        swoole_process::wait();
    }
}