<?php
swoole_async_read(__DIR__.'/../server.php', function($filename, $content){
	echo "file: $filename\ncontent-length: ".strlen($content)."\nContent:\n";
	return false;
}, 8192);
