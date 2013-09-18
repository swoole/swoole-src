<?php
error_reporting(E_ALL);

//启用多少个进程
$proc_cnt = isset($argv[1]) ? intval($argv[1]) : 10;
//每个进程发送多少请求
$req_cnt = isset($argv[2]) ? intval($argv[2]) : 100000;

echo "c = $proc_cnt | n = $req_cnt\n";

$pid_array = array();

$time_start = microtime(true);
$suc_cnt = 0;
$fail_cnt = 0;
$j = $proc_cnt;
//while ($j-- != 0)
//{
//    $pid = pcntl_fork();
//    if ($pid > 0)
//    {
//        $pid_array[$pid] = $pid;
//    }
//    else
//    {
//        $i = $req_cnt;
//        while ($i-- > 0)
//        {
//            send_request();
//        }
//        print_result();
//        exit("");
//    }
//}

function send_request()
{
//    $data = file_get_contents('/tmp/ispace.log');
        $client = new swoole_client(SWOOLE_SOCK_TCP); //同步阻塞
        if($client->connect('127.0.0.1', 9500, 0.5) == false)
        {
			echo "connect fail\n";
			return false;
		}
        for($i=0; $i < 1000; $i++)
        {
            $client->send("hello world");
            $data = $client->recv(80000);
            if($data === false)
            {
				echo "recv fail\n";
				return false;
			}
        }
        echo "$i: ".$data . "\n";
        unset($client);
//        $client->close();
}

function print_result($cnt = null)
{
    global $fail_cnt, $time_start, $proc_cnt, $req_cnt;
    if ($cnt == null) $cnt = $req_cnt;
    echo "\n", $cnt / (microtime(true) - $time_start), "req/S fail count $fail_cnt\n";
}

while (!empty($pid_array))
{
    $pid = pcntl_wait($status);
    if ($pid > 0)
    {
        unset($pid_array[$pid]);
    }
}

for($i=0; $i< $req_cnt; $i++)
{
    send_request();
}

echo "DONE ........";
print_result($req_cnt * $proc_cnt);


