<?php
Swoole\Event::add(STDIN, function($fp) {
	echo "STDIN: ".fread($fp, 8192);
});
Swoole\Event::wait();
