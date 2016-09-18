<?php
/**
 * @Author: winterswang
 * @Date:   2015-06-18 16:45:09
 * @Last Modified by:   winterswang
 * @Last Modified time: 2016-09-18 17:33:51
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

		// $udp = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC);
		// $udp->on("connect", function(swoole_client $cli) {
		//     $cli->send("udp test");
		// });
		// $udp->on("receive", function(swoole_client $cli, $data)use($response){

			$tcp = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
			$tcp->on("connect", function(swoole_client $cli) {
			    $cli->send("tcp test");
			});
			$tcp->on("receive", function(swoole_client $cli, $data)use($response){
				$response ->end("<h1> swoole response</h1>");
			});
			$tcp->on("close", function(swoole_client $cli){
			});
			$tcp->on("error", function(swoole_client $cli){
			});			
			$tcp->connect('10.100.64.151', 9805);		

		// });
		// $udp->on("close", function(swoole_client $cli){
		// });
		// $udp->connect('10.100.65.222', 9906);

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
		'worker_num' => 4,
		'dispatch_mode' => 2,   //固定分配请求到worker
		'reactor_num' => 4,     //亲核
		'daemonize' => 1,       //守护进程
		'backlog' => 128,
		'log_file' => '/data/log/test_http_server.log', 
);
$th = new TestHttpServer();
$th ->set($setting);
$th ->start();