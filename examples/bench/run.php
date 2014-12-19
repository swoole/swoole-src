<?php
//关闭错误输出
//error_reporting(0);
$shortopts = "c:";
$shortopts .= "n:";
$shortopts .= "s:";
$shortopts .= "f:";
$shortopts .= "p::";

$opt = getopt($shortopts);
//并发数量
if(!isset($opt['c'])) exit("require -c [process_num]. ep: -c 100\n");
if(!isset($opt['n'])) exit("require -n [request_num]. ep: -n 10000\n");
if(!isset($opt['s'])) exit("require -s [server_url]. ep: -s tcp://127.0.0.1:9999\n");
if(!isset($opt['f'])) exit("require -f [test_function]. ep: -f short_tcp\n");

$bc = new Swoole_Benchmark(trim($opt['f']));
$bc->process_num = (int)$opt['c'];
$bc->request_num = (int)$opt['n'];
$bc->server_url = trim($opt['s']);
$bc->server_config = parse_url($bc->server_url);
$bc->send_data = "GET /hello.html HTTP/1.1\r\n";
$bc->send_data .= "Host: 127.0.0.1\r\n";
$bc->send_data .= "Connection: keep-alive\r\n";
$bc->send_data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
$bc->send_data .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n\r\n";

$bc->read_len = 65536;
if(!empty($opt['p'])) $bc->show_detail = true;


function eof(Swoole_Benchmark $bc)
{
    static $fp = null;
    static $i;
    $start = microtime(true);
    if(empty($fp))
    {
        $fp = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $end = microtime(true);
        $conn_use = $end-$start;
        $bc->max_conn_time = $conn_use;
        $i = 0;
        //echo "connect {$bc->server_url} \n";
        if (!$fp->connect($bc->server_config['host'], $bc->server_config['port'], 2))
        {
            error:
            echo "Error: ".swoole_strerror($fp->errCode)."[{$fp->errCode}]\n";
            $fp = null;
            return false;
        }
        $start = $end;
    }
    /*--------写入Sokcet-------*/
    $data = str_repeat('A', rand(2000, 4000)."\r\n\r\n");
    if (!$fp->send($data))
    {
        goto error;
    }
    $end = microtime(true);
    $write_use = $end - $start;
    if($write_use > $bc->max_write_time) $bc->max_write_time = $write_use;
    $start = $end;
    /*--------读取Sokcet-------*/
    while(true)
    {
        $ret = $fp->recv(65530);
        if (empty($ret) or substr($ret, -1, 1) == "\n")
        {
            break;
        }
    }
    //var_dump($ret);
    $i++;
    if (empty($ret))
    {
        echo $bc->pid,"#$i@"," is lost\n";
        return false;
    }
    $end = microtime(true);
    $read_use = $end - $start;
    if($read_use>$bc->max_read_time) $bc->max_read_time = $read_use;
    return true;
}

function long_tcp(Swoole_Benchmark $bc)
{
	static $fp = null;
	static $i;
	$start = microtime(true);
	if(empty($fp))
	{
		$fp = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
		$end = microtime(true);
		$conn_use = $end-$start;
		$bc->max_conn_time = $conn_use;
		$i = 0;
		//echo "connect {$bc->server_url} \n";
		if (!$fp->connect($bc->server_config['host'], $bc->server_config['port'], 2))
		{
			error:
			echo "Error: ".swoole_strerror($fp->errCode)."[{$fp->errCode}]\n";
			$fp = null;
			return false;
		}
		$start = $end;
	}
	/*--------写入Sokcet-------*/
	if(!$fp->send($bc->send_data))
	{
		goto error;
	}
	$end = microtime(true);
	$write_use = $end - $start;
	if($write_use > $bc->max_write_time) $bc->max_write_time = $write_use;
	$start = $end;
	/*--------读取Sokcet-------*/
	while(true)
	{
		$ret = $fp->recv(65530);
		if (empty($ret) or substr($ret, -1, 1) == "\n")
		{
			break;
		}
	}
	//var_dump($ret);
	$i++;
	if (empty($ret))
	{
		echo $bc->pid,"#$i@"," is lost\n";
		return false;
	}
	$end = microtime(true);
	$read_use = $end - $start;
	if($read_use>$bc->max_read_time) $bc->max_read_time = $read_use;
	return true;
}

/**
 * 去掉计时信息的UDP
 * @param $bc
 */
function udp(Swoole_Benchmark $bc)
{
	static $fp;
	if(empty($fp))
	{
		$fp = stream_socket_client($bc->server_url, $errno, $errstr, 1);
		if(!$fp)
		{
			echo "{$errstr}[{$errno}]\n";
			return false;
		}
	}
	/*--------写入Sokcet-------*/
	fwrite($fp, $bc->send_data);
	/*--------读取Sokcet-------*/
	$ret = fread($fp, $bc->read_len);
	if(empty($ret)) return false;
	return true;
}

function udp2(Swoole_Benchmark $bc)
{
	static $fp;
	$start = microtime(true);
	if(empty($fp))
	{
		$u = parse_url($bc->server_url);
		$fp = new swoole_client(SWOOLE_SOCK_UDP);
		$fp->connect($u['host'], $u['port'], 0.5, 0);
		$end = microtime(true);
		$conn_use = $end-$start;
		$bc->max_conn_time = $conn_use;
		$start = $end;
	}
	/*--------写入Sokcet-------*/
	$fp->send($bc->send_data);
	$end = microtime(true);
	$write_use = $end - $start;
	if($write_use > $bc->max_write_time) $bc->max_write_time = $write_use;
	$start = $end;
	/*--------读取Sokcet-------*/
	$ret = $fp->recv();
	if(empty($ret)) return false;

	$end = microtime(true);
	$read_use = $end - $start;
	if($read_use>$bc->max_read_time) $bc->max_read_time = $read_use;
	return true;

}

function short_tcp($bc)
{
	$fp = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
	if(!$fp->connect($bc->server_config['host'], $bc->server_config['port'], 1))
	{
		error:
		echo "Error: {$fp->errMsg}[{$fp->errCode}]\n";
		return false;
	}
	else
	{
		if(!$fp->send($bc->send_data))
		{
			goto error;
		}
		$ret = $fp->recv();
		$fp->close();
		if(!empty($ret)) return true;
		else return false;
	}
	usleep(100);
}
//请求数量最好是进程数的倍数
$bc->process_req_num = intval($bc->request_num/$bc->process_num);
$bc->run();
$bc->report();
$bc->end();

class Swoole_Benchmark
{
	public $test_func;
	public $process_num;
	public $request_num;
	public $server_url;
	public $server_config;
	public $send_data;
	public $read_len;

	public $time_end;
	private $shm_key;
	public $main_pid;
	public $child_pid = array();

	public $show_detail = false;
	public $max_write_time = 0;
	public $max_read_time = 0;
	public $max_conn_time = 0;

    public $pid;

	function __construct($func)
	{
		if(!function_exists($func))
		{
			exit(__CLASS__.": function[$func] not exists\n");
		}
		$this->test_func = $func;
	}
	function end()
	{
		unlink($this->shm_key);
		foreach($this->child_pid as $pid)
		{
			unlink('/dev/shm/lost_'.$pid.'.log');
		}
	}
	function run()
	{
		$this->main_pid = posix_getpid();
		$this->shm_key = "/dev/shm/t.log";
		for($i=0;$i<$this->process_num;$i++)
		{
			$this->child_pid[] = $this->start(array($this,'worker'));
		}
		for($i=0;$i<$this->process_num;$i++)
		{
			$status = 0;
			$pid = pcntl_wait($status);
		}
		$this->time_end = microtime(true);
	}

	function init_signal()
	{
		pcntl_signal(SIGUSR1,array($this, "sig_handle"));
	}

	function sig_handle($sig)
	{
		switch ($sig)
		{
			case SIGUSR1:
				return;
		}
		$this->init_signal();
	}

	function start($func)
	{
		$pid = pcntl_fork();
		if($pid>0)
		{
			return $pid;
		}
		elseif($pid==0)
		{
			$this->worker();
		}
		else
		{
			echo "Error:fork fail\n";
		}
	}
	function worker()
	{
		$lost = 0;
		if(!file_exists($this->shm_key))
		{
			file_put_contents($this->shm_key,microtime(true));
		}
		if($this->show_detail) $start = microtime(true);
		$this->pid = posix_getpid();

		for($i=0;$i<$this->process_req_num;$i++)
		{
			$func = $this->test_func;
			if(!$func($this)) $lost++;
		}
		if($this->show_detail)
		{
			$log  = $pid."#\ttotal_use(s):".substr(microtime(true)-$start,0,5);
			$log .= "\tconnect(ms):".substr($this->max_conn_time*1000,0,5);
			$log .= "\twrite(ms):".substr($this->max_write_time*1000,0,5);
			$log .= "\tread(ms):".substr($this->max_read_time*1000,0,5);
			file_put_contents('/dev/shm/lost_'.$this->pid.'.log', $lost."\n".$log);
		}
		else
		{
			file_put_contents('/dev/shm/lost_'.$this->pid.'.log', $lost);
		}
		exit(0);
	}
	function report()
	{
		$time_start = file_get_contents($this->shm_key);
		$usetime = $this->time_end - $time_start;
		$lost = 0;

		foreach ($this->child_pid as $f)
		{
			$_lost = file_get_contents('/dev/shm/lost_'.$f.'.log');
			$log = explode("\n",$_lost,2);
			if(!empty($log))
			{
				$lost += intval($log[0]);
				if($this->show_detail) echo $log[1],"\n";
			}
		}
		//并发量
		echo "concurrency:\t".$this->process_num,"\n";
		//请求量
		echo "request num:\t".$this->request_num,"\n";
		//请求量
		echo "lost num:\t".$lost,"\n";
		//请求量
		echo "success num:\t".($this->request_num-$lost),"\n";
		//总时间
		echo "total time:\t".substr($usetime,0,5),"\n";
		//每秒处理能力
		echo "req per second:\t".intval($this->request_num/$usetime),"\n";
		//每次请求平均时间ms
		echo "one req use(ms):\t".substr($usetime/$this->request_num*1000,0,5),"\n";
	}
}

