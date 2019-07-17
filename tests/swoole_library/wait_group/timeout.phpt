--TEST--
swoole_library/wait_group: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
	$start_time = microtime(1);
    $wg = new Swoole\Coroutine\WaitGroup;
	$ret = [];
    for($i=0;$i<10;$i++) {
        $wg->add();
        go(function() use ($wg, $i, &$ret) {		
			$time = rand(5,15)/10;
            co::sleep($time);			
			$ret[$i] = $time;
            $wg->done();
        });
    }
    $std_time = 1;
	$wg->wait($std_time);
	$end_time = microtime(1);
	$used_time = $end_time - $start_time;
	echo "all done, use time $used_time\n";
	Assert::assert(abs($std_time - $used_time) < 0.5);
});
?>
--EXPECTF--
all done, use time %s
