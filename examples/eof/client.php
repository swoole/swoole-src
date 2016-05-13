<?php
/**
 * 分段发送数据
 *
 * @param swoole_client $client
 * @param string        $data
 * @param int           $chunk_size
 */
function send_chunk(swoole_client $client, $data, $chunk_size = 1024)
{
	$len = strlen($data);
	$chunk_num = intval($len / $chunk_size) + 1;
	for ($i = 0; $i < $chunk_num; $i++)
	{
		if ($len < ($i + 1) * $chunk_size)
		{
			$sendn = $len - ($i * $chunk_size);
		}
		else
		{
			$sendn = $chunk_size;
		}
		$client->send(substr($data, $i * $chunk_size, $sendn));
	}
}

$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
if(!$client->connect('127.0.0.1', 9501, 0.5, 0))
{
	echo "Over flow. errno=".$client->errCode;
	die("\n");
}

//for ($i = 0; $i < 10; $i++)
//{
//    $client->send("hello world\r\n\r\n");
//    echo "send\n";
//}
//exit;

$data = array(
	'name' => __FILE__,
	'content' => str_repeat('A', 8192 * rand(1, 3)),  //800K
);

$_serialize_data = serialize($data);

$_send = $_serialize_data."__doit__";

echo "serialize_data length=".strlen($_serialize_data)."send length=".strlen($_send)."\n";
//send_chunk($client, $_send);

//
if(!$client->send($_send))
{
	die("send failed.\n");
}

//$client->send("\r\n".substr($_serialize_data, 0, 8000));

echo $client->recv();
exit;

$client->send(substr($_serialize_data, 8000));

//usleep(500000);

if (!$client->send("\r\n\r\n"))
{
	die("send failed.\n");
}

echo $client->recv();

//sleep(1);
