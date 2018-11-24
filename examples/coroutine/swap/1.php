<?php
co::onSwapIn(function($cid) {
	echo "hook:onSwapIn $cid\n";
});
co::onSwapOut(function($cid) {
	echo "hook:onSwapOut $cid\n";
});
go(function () {	
    echo "start coro ".co::getuid()."\n";
	co::sleep(0.5);
	go(function () {
		echo "start coro ".co::getuid()."\n";
		co::sleep(0.5);
		go(function () {
			echo "start coro ".co::getuid()."\n";
			co::sleep(0.5);
			echo "end coro ".co::getuid()."\n";
		});
		echo "end coro ".co::getuid()."\n";
	});
    echo "end coro ".co::getuid()."\n";
});

go(function () {
	echo "start coro ".co::getuid()."\n";
	co::sleep(0.5);
	echo "end coro ".co::getuid()."\n";
});
echo "main end\n";
    
