<?php
if (empty($argv[1]))
{
	$server_ip = '127.0.0.1';
}
else
{
	$server_ip = $argv[1];
}
$cli = new swoole_client(SWOOLE_TCP);
$cli->connect($server_ip, 9501, 5);
$filesize = intval($cli->recv());
if ($filesize == 0)
{
	die("get file size failed.\n");
}
echo "file_size = $filesize\n";
$content = '';
$cli->send("get file");
while(1)
{
	$content .= $cli->recv();
    echo strlen($content)."\n";
	if(strlen($content) == $filesize)
	{
        $i = time();
		file_put_contents(__DIR__."/recv_file_{$i}.jpg", $content);
		break;
	}
}
$cli->close();
