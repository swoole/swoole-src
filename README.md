php_swoole
==========

PHP extension.A socket server framework.

example:
==========
<pre>
	<?php
	$serv = swoole_server_create("127.0.0.1", 9500, 1);
	swoole_server_set($serv, array(
	    'timeout'=>2.5,
	    'poll_thread_num'=>1,
	    'writer_num'=>2,
	    'worker_num'=>2,
	    'backlog'=>128,
	));
	function my_onStart($serv)
	{
	    echo "Server：start\n";
	}
	
	function my_onShutdown($serv)
	{
	    echo "Server：onShutdown(\n";
	}
	
	function my_onClose($serv,$fd,$from_id)
	{
	  echo "Client：Close. fd=$fd|from_id=$from_id\n";
	}
	
	function my_onConnect($serv,$fd,$from_id)
	{
		echo "Client：Connect. fd=$fd|from_id=$from_id\n";
	}
	
	function my_onReceive($serv,$fd,$from_id,$data)
	{
		echo "Client：Data. fd=$fd|from_id=$from_id|data=$data\n";
		swoole_server_send($serv, $fd, "Server:$data");
	}
	
	swoole_server_handler($serv, 'onStart', 'my_onStart');
	swoole_server_handler($serv, 'onConnect', 'my_onConnect');
	swoole_server_handler($serv, 'onReceive', 'my_onReceive');
	swoole_server_handler($serv, 'onClose', 'my_onClose');
	swoole_server_handler($serv, 'onShutdown', 'my_onShutdown');
	
	swoole_server_start($serv);
	?>
</pre>