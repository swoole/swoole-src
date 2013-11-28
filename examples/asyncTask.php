<?php
$code = "require 'func.php';
return test(1, 'hello world');";
//忽略返回值
swoole_async_task($code); 
//处理返回值
swoole_async_task($code, function($result){
	echo $result;
});

?>
选择直接发送PHP code，还是发送函数名+参数？


调用此函数时检测 运行环境。第一次调用async_task时
Client环境：创建reactor和ProcessPool。有返回值则将pipe加入reactor，并启动reactor。此时进入阻塞
Server环境：PocessPool已创建好。只需要加入reactor即可。
