<?php
swoole_async_readfile(__DIR__.'/../server.php', function($filename, $content){
	echo "file: $filename\ncontent-length: ".strlen($content)."\nContent:\n";
	swoole_async_writefile(__DIR__.'/test.copy', $content, function($write_file) {
		echo "file: $write_file\n";
		swoole_event_exit();
	});
});
