<?php
// Swoole\Table counters are safe to update from several workers.
// Run: php examples/table/incr_decr.php
$table = new Swoole\Table(1024);
$table->column('hits', Swoole\Table::TYPE_INT);
$table->create();
$table->set('page', ['hits' => 0]);
echo 'after incr: ', $table->incr('page', 'hits', 5), PHP_EOL;
echo 'after decr: ', $table->decr('page', 'hits', 2), PHP_EOL;
echo 'final value: ', $table->get('page', 'hits'), PHP_EOL;
