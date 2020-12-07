--TEST--
swoole_coroutine_scheduler: getOptions
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = new Co\Scheduler;
$sch->set(['max_coroutine' => 100, 'deadlock_check_max_stack' => 64, ]);
$options = $sch->getOptions();
ASsert::isArray($options);
Assert::eq($options['deadlock_check_max_stack'], 64);
?>
--EXPECT--
