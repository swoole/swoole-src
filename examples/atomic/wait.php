<?php
$n = new swoole_atomic(0);

if (pcntl_fork() > 0)
{
	echo "master start\n";
	$n->wait(1.5);
	echo "master end\n";
}
else
{
	echo "child start\n";
	sleep(1);
	$n->wakeup();
	echo "child end\n";
}
