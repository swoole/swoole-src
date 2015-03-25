<?php
$clients = array();
for($j = 0; $j < 2; $j++)
{
	$pid = pcntl_fork();
	if($pid > 0)
	{
		continue;
	}
	else
	{
		for($i = 0; $i < 9999; $i++){
			$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
			$ret = $client->connect('127.0.0.1', 9501, 0.5);
			if(!$ret)
			{
				echo "#$i\tConnect fail.  errno=".$client->errCode;
				die("\n");
			}
			$clients[] = $client;
			usleep(10);
		}
		echo "Worker #".posix_getpid()." connect $i finish\n";
		sleep(1000);
		exit;
	}
}
sleep(1000);

