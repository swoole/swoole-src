<?php
/**
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

// 初始化一个容量为 1024 的 Swoole Table
$table = new \Swoole\Table(1024);
// 在 Table 中新增 id 列
$table->column('id', \Swoole\Table::TYPE_INT);
// 在 Table 中新增 name 列
$table->column('name', \Swoole\Table::TYPE_STRING, 3);
// 在 Table 中新增 num 列
$table->column('num', \Swoole\Table::TYPE_FLOAT);

// 创建 Swoole Table
$table->create();

// 设置 Key-Value 值
$table->set('developer-1', ['id' => 1, 'name' => 'PHP', 'num' => 3]);
$table->set('developer-2', ['id' => 2, 'name' => 'Swoole', 'num' => 4]);

// 迭代器遍历
foreach($table as $row)
{
    var_dump($row);
}
echo count($table) . PHP_EOL;

// 如果指定 Key 值存在则打印对应 Value 值
if ($table->exist('developer-1')) {
    echo "developer-" . $table->get('developer-1', 'id') . ':' . $table->get('developer-1', 'name')  . ':' . $table->get('developer-1', 'num') . PHP_EOL;
}

// 自增操作
$table->incr('developer-2', 'num', 5);
var_dump($table->get('developer-2'));
// 自减操作
$table->decr('developer-2', 'num', 5);
var_dump($arr = $table->get('developer-2'));

// 表中总记录数
$count = $table->count();
var_dump($count);

// 删除指定表记录
$table->del('developer-1');
var_dump($table->exist('developer-1'));
