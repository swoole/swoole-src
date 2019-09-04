<?php
ini_set('memory_limit', '8M');

$table = new Swoole\Table(1024);
$table->column('name', swoole_table::TYPE_STRING, 1024 * 64);
$table->create();

$table->set('key1', ['name' => str_repeat('A', 1024 * 64 - 1) . "\n"]);

if (pcntl_fork() == 0) {
    sleep(1);
    $r = $table->get('key1');
    var_dump(strlen($r['name']));
} else {
    $mu1 = memory_get_usage();
    var_dump($mu1);
    $str = str_repeat('A', 1024 * 1024 * 5);
    $str2 = str_repeat('A', 1024 * 1024);
    $str3 = str_repeat('A', 1024 * 64);
    var_dump(memory_get_usage());
    $r = $table->get('key1');
    var_dump(strlen($r['name']));
    echo substr($str, 0, 8);
    pcntl_wait($status);
}

