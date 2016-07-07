<?php
/**
 * @Author: winterswang
 * @Date:   2015-06-18 16:45:09
 * @Last Modified by:   winterswang
 * @Last Modified time: 2016-06-28 17:48:58
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

		$this ->http = new swoole_http_server($this ->setting['host'], $this ->setting['port']);
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

		$multi = new swoole_multi();
		$udp_cli = new swoole_client_coro(SWOOLE_SOCK_UDP);
		$tcp_cli = new swoole_client_coro(SWOOLE_SOCK_TCP);
		
		$ret = $udp_cli ->connect('127.0.0.1', 9906);
		$ret = $tcp_cli ->connect("127.0.0.1", 9805);

		$multi->add(['AAAA' => $udp_cli, 'BBBB' => $tcp_cli]);

		$ret = $udp_cli ->send('test for the coro');
		$ret = $udp_cli ->recv();
  		
		$ret = $tcp_cli ->send('test for the coro');
		$ret = $tcp_cli ->recv();

		$ret = $multi->recv();		
		$tcp_cli ->close();
		$udp_cli ->close();

		$response ->end(" swoole response is  ret == " . print_r($ret, true));
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
		'port' => 10005,
		'worker_num' => 1,
		'dispatch_mode' => 2,   //固定分配请求到worker
		'reactor_num' => 4,     //亲核
		'daemonize' => 1,       //守护进程
		'backlog' => 128,
		'log_file' => '/data/log/test_http_server.log', 
);
$th = new TestHttpServer();
$th ->set($setting);
$th ->start();




