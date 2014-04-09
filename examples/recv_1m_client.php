<?php
$c = new swoole_client(SWOOLE_TCP);
$f = fopen('data.log', 'w');
$c->connect('10.73.8.114', 9509, 60);
$c->send("AAAAAAAAAAAAAAAA");

while(true)
{
	$line = $c->recv();
	if($line) fwrite($f, $line);
	else 
	{
		echo "recv failed.\n";
		break;
	}
}


