<?php
swoole_async::set(['aio_mode' => SWOOLE_AIO_LINUX]);

swoole_async_readfile(__DIR__.'/../test.jpg', function($filename, $content){
	echo "file: $filename\ncontent-length: ".strlen($content)."\nContent:\n";
	swoole_async_writefile(__DIR__.'/test.copy', $content, function($write_file) {
		echo "file: $write_file\n";
		swoole_event_exit();
	});
});
