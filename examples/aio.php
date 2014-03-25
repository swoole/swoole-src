<?php
swoole_async_readfile(__DIR__.'/server.php', function($filename, $content){
	echo "file: $filename\ncontent-length: ".strlen($content);
	//swoole_async_writefile(__DIR__.'/test.log', str_repeat('B', 1024), function($write_file){
	//	echo "file: $write_file\n";
	//	swoole_event_exit();
	//});
});
