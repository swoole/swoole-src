--TEST--
swoole_library/wait_group: base
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    $wg = new Swoole\Coroutine\WaitGroup;
	$ret = [];
    for($i=0;$i<10;$i++) {
        $wg->add();
        go(function() use ($wg, $i, &$ret) {		
            co::sleep(0.1);			
			$ret[$i] = $i;
            $wg->done();
        });
    }
	$wg->wait();
	Assert::assert(count($ret) == 10);
});
?>
--EXPECTF--
