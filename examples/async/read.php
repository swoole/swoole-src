<?php
ini_set("swoole.aio_mode", 2);
swoole_async_read(__DIR__.'/data.txt', function($filename, $content){
	echo "file: $filename\ncontent-length: ".strlen($content)."\nContent: $content\n";
	if (empty($content)) {
		echo "file is end.\n";
		swoole_event_exit();
		return false;
	} else {
		return true;
	}
}, 8192);
