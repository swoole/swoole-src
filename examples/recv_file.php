<?php
$cli = new swoole_client(SWOOLE_TCP);
$cli->connect('127.0.0.1', 9501, 0.5);
$filesize = intval($cli->recv());
echo "file_size = $filesize\n";
$content = '';
$cli->send("get file");
while(1)
{
	$content .= $cli->recv();
	if(strlen($content) == $filesize)
	{
		file_put_contents(__DIR__.'/recv_file.jpg', $content);
		break;
	}
}
$cli->close();
