<?php
/**
 * @Author: winterswang
 * @Date:   2015-06-18 16:45:09
 * @Last Modified by:   winterswang
 * @Last Modified time: 2016-09-18 17:36:18
 */

class TestHttpServer {

	public $http;
	public $queue;
	public $setting = array();

	/**
	 * [__construct description]
	 * @param array $setting [description]
	 */
	public function __construct(){

	}

	public function set($setting){

		$this ->setting = $setting;
	}

	/**
	 * [init description]
	 * @return [type] [description]
	 */
	public function init(){

		if (!isset($this ->setting['host'])) {
			$this ->setting['host'] = '0.0.0.0';
		}
		if (!isset($this ->setting['port'])) {
			$this ->setting['port'] = '9999';
		}

		$this ->http = new Swoole\Http\Server($this ->setting['host'], $this ->setting['port']);
		$this ->http ->set($this ->setting);

		$this ->http ->on('request', array($this, 'onRequest'));
		$this ->http ->on('close', array($this, 'onClose'));
	}

	/**
	 * [onRequest description]
	 * @param  [type] $request  [description]
	 * @param  [type] $response [description]
	 * @return [type]           [description]
	 */
	public function onRequest($request, $response){

		
		//$udp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
		$tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);

		// $ret = $udp_cli ->connect('10.100.65.222', 9906);
		// $ret = $udp_cli ->send('test for the coro');
		// $ret = $udp_cli ->recv(100);
		// $udp_cli->close();

		// if ($ret) {
		// 	//error_log(" udp cli get rsp == " . print_r($ret, true),3, '/data/log/udp_timeout.log');
		// }
		// else{
		// 	error_log(" udp cli timeout \n",3, '/data/log/udp_timeout.log');
		// }

  		$ret = $tcp_cli ->connect("10.100.64.151", 9805);
		$ret = $tcp_cli ->send('test for the coro');
		$ret = $tcp_cli ->recv(100);
		$tcp_cli->close();

		if ($ret) {
			//error_log(" tcp cli get rsp == " . print_r($ret, true) . PHP_EOL, 3, '/data/log/udp_timeout.log');
		}
		else{
			error_log(" tcp cli timeout \n",3, '/data/log/udp_timeout.log');
		}
		
		$response ->end(" swoole response is ok");
	}

	/**
	 * [onClose description]
	 * @param  [type] $server  [description]
	 * @param  [type] $fd      [description]
	 * @param  [type] $from_id [description]
	 * @return [type]          [description]
	 */
	public function onClose($server, $fd, $from_id){
		
		//echo " on close fd = $fd from_id = $from_id \n";
	}

	/**
	 * [start description]
	 * @return [type] [description]
	 */
	public function start(){

		$this ->init();
		$this ->http ->start();
	}
}

$setting = array(
		'host' => '0.0.0.0',
		'port' => 10006,
		'worker_num' => 4,
		'dispatch_mode' => 3,   //固定分配请求到worker
		'reactor_num' => 4,     //亲核
		'daemonize' => 1,       //守护进程
		'backlog' => 128,
		'log_file' => '/data/log/test_http_server.log', 
);
$th = new TestHttpServer();
$th ->set($setting);
$th ->start();




