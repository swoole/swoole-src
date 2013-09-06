swoole_connection_list遍历所有连接
-----
用来遍历当前Server所有的客户端连接
> 需要swoole-1.5.8以上版本

函数原型：
```php
swoole_connection_list(resource $serv, int $start_fd = 0, int $pagesize = 10);
```

此函数接受3个参数，第一个参数是server的资源对象，第二个参数是起始fd，第三个参数是每页取多少条，最大不得超过100.  
* 调用成功将返回一个数字索引数组，元素是取到的$fd。数组会按从小到大排序。最后一个$fd作为新的start_fd再次尝试获取
* 调用失败返回false

示例：
```php
$start_fd = 0;
while(true)
{
	$conn_list = swoole_connection_list($serv, $start_fd, 10);
	if($conn_list===false)
	{
		echo "finish\n";
		break;
	}
	$start_fd = $conn_list[count($conn_list)-1];
	var_dump($conn_list);
}
```
