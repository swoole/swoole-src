--TEST--
swoole_table: stats
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

define('N',  IS_IN_TRAVIS ? 10000 : 100000);

$table = new Table(N);
$table->column('string', Table::TYPE_STRING, 256);
$table->create();

$map = [];
$keys = [];

$n = N;
while ($n--) {
    $key = base64_decode(RandStr::getBytes(rand(10, 30)));
    $value = RandStr::getBytes(rand(100, 250));
    if ($table->set($key, ['string' => $value])) {
        $map[$key] = $value;
        $keys[] = $key;
    }
}

$stats1 = $table->stats();

Assert::eq(count($keys), N);
Assert::eq(count(array_unique($keys)), $stats1['insert_count']);

phpt_var_dump("insert\n".str_repeat('-', 64), $stats1);

define('UPDATE_N', rand(100, 1000));

$_n = UPDATE_N;
while ($_n--) {
    $key = array_rand($map);
    $value = RandStr::getBytes(rand(100, 250));
    Assert::true($table->set($key, ['string' => $value]));
    $map[$key] = $value;
}

$stats2 = $table->stats();
Assert::eq($stats1['update_count'] + UPDATE_N, $stats2['update_count']);
phpt_var_dump("update\n" . str_repeat('-', 64), $stats2);

foreach($map as $k => $v) {
    Assert::same($table->get($k)['string'], $v);
    $table->del($k);
}

$stats3 = $table->stats();
Assert::eq($stats3['num'], 0);
Assert::eq($stats3['available_slice_num'], $stats3['total_slice_num']);
phpt_var_dump("delete\n" . str_repeat('-', 64), $stats3);
?>
--EXPECT--
