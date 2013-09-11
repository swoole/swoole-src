swoole_server_handler设置事件回调
=====
设置Server的事件回调函数，原型：
```php
bool swoole_server_handler(resource $serv, string $event_name, mixed $event_callback_function);
```

示例：
```php
swoole_server_handler($serv, 'onStart', 'my_onStart');
function my_onStart($serv)
{
    echo "Server：start\n";
}
```

* 第一个参数是swoole的资源对象  
* 第二个参数是回调的名称, 大小写不敏感，具体内容参考回调函数列表  
* 第三个函数是回调的PHP函数，可以是字符串，数组，匿名函数。比如  


```php
swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onStart', array($this, 'my_onStart'));
swoole_server_handler($serv, 'onStart', 'myClass::onStart');
```

设置成功后返回true。如果$event_name填写错误将返回false。

> onConnect/onClose/onReceive这3个回调函数必须设置。其他事件回调函数可选  
> 如果设定了timer定时器，onTimer事件回调函数也必须设置





