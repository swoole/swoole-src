<?php
include __DIR__.'/lib/class.websocket_client.php';

function swoole_php_fork($code, $out = false) {
	$func = create_function('$worker', $code);
	$process = new swoole_process($func, $out);
	$pid = $process->start();
	
	register_shutdown_function(
            function($pid,$process) {
				swoole_process::kill($pid);
				$process->wait();
            },
            $pid,$process
    );
	
	return $process;
}

