<?php
// This example writes a temporary file; remove it on exit to keep the tree clean.
register_shutdown_function(function () {
    foreach (glob(__DIR__ . '/data.txt') as $file) {
        @unlink($file);
    }
});
Swoole\Runtime::enableCoroutine();
Co\run(function() {
	$fp = fopen(__DIR__ . '/data.txt', 'w+');
	echo "open\n";
	fwrite($fp, str_repeat('A', 1024));
	fwrite($fp, str_repeat('B', 1024));
	echo "fwrite\n";
	echo fread($fp, 1024);
	echo "fread\n";
	include __DIR__."/include.php";
	echo "include\n";
	var_dump(fstat($fp));
	echo "fstat\n";
	fseek($fp, 0);
	echo "fseek\n";
	fclose($fp);
});
