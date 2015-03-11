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
$start_ms = microtime(true);
$cli->connect($server_ip, 9501, 5);
$filesize = intval($cli->recv());
if ($filesize == 0)
{
    die("get file size failed.\n");
}
echo "file_size = $filesize\n";
$content = '';
$cli->send("get file");

$use_waitall = false;

if ($use_waitall)
{
    //waitall，需要一次性分配内存，适合小一点的文件
    $content = $cli->recv($filesize, true);
}
else
{
    //循环接收，适合大型文件
    while(1)
    {
        //超大文件接收，这里需要改成分段写磁盘
        $content .= $cli->recv();
        if (strlen($content) == $filesize)
        {
            break;
        }
    }
}
file_put_contents(__DIR__."/recv_file_".time().".jpg", $content);
echo "recv ".strlen($content)." byte data\n";
echo "used ".((microtime(true) - $start_ms)*1000)."ms\n";
$cli->close();
