# 协程客户端 <!-- {docsify-ignore-all} -->

下列协程客户端是Swoole内置的类，其中标有 ⚠️ 标志的不推荐再继续使用，可以使用PHP原生的函数+[一键协程化](/runtime)。

* [TCP/UDP/UnixSocket客户端](coroutine_client/client.md)
* [Socket客户端](coroutine_client/socket.md)
* [HTTP/WebSocket客户端](coroutine_client/http_client.md)
* [HTTP2客户端](coroutine_client/http2_client.md)
* [PostgreSQL客户端](coroutine_client/postgresql.md)
* [FastCGI客户端](coroutine_client/fastcgi.md)
* ⚠️ [Redis客户端](coroutine_client/redis.md)
* ⚠️ [MySQL客户端](coroutine_client/mysql.md)
* [System](/coroutine/system)系统API

## 超时规则

所有的网络请求(建立连接，发送数据，接收数据)都有可能超时，`Swoole`协程客户端设置超时的方式有三种：

1. 通过方法的参数传入超时时间，例如[Co\Client->connect()](/coroutine_client/client?id=connect)、[Co\Http\Client->recv()](/coroutine_client/http_client?id=recv)、[Co\MySQL->query()](/coroutine_client/mysql?id=query)等

!> 这种方式的影响范围最小(只针对当前这次函数调用生效)，优先级最高(当前这次函数调用将无视下面的`2`、`3`设置)。

2. 通过`Swoole`协程客户端类的`set()`或`setOption()`方法设置超时，例如：

```php
$client = new Co\Client(SWOOLE_SOCK_TCP);
//或
$client = new Co\Http\Client("127.0.0.1", 80);
//或
$client = new Co\Http2\Client("127.0.0.1", 443, true);
$client->set(array(
    'timeout' => 0.5,//总超时，包括连接、发送、接收所有超时
    'connect_timeout' => 1.0,//连接超时，会覆盖第一个总的 timeout
    'write_timeout' => 10.0,//发送超时，会覆盖第一个总的 timeout
    'read_timeout' => 0.5,//接收超时，会覆盖第一个总的 timeout
));

//Co\Redis() 没有 write_timeout 和 read_timeout 配置
$client = new Co\Redis();
$client->setOption(array(
    'timeout' => 1.0,//总超时，包括连接、发送、接收所有超时
    'connect_timeout' => 0.5,//连接超时，会覆盖第一个总的 timeout 
));

//Co\MySQL() 没有 set 配置的功能
$client = new Co\MySQL();

//Co\Socket 通过 setOption 配置
$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);
$timeout = array('sec'=>1, 'usec'=>500000);
$socket->setOption(SOL_SOCKET, SO_RCVTIMEO, $timeout);//接受数据超时时间
$socket->setOption(SOL_SOCKET, SO_SNDTIMEO, $timeout);//连接超时和发送数据超时的配置
```

!> 这种方式的影响只针对当前类生效，会被第`1`种方式覆盖，无视下面的第`3`种方式配置。

3. 可以看到上面`2`种方式超时设置规则很麻烦且不统一，为了避免开发者需要处处谨慎设置，从`v4.2.10`版本开始所有协程客户端提供了全局统一超时规则设置，这种影响最大，优先级最低，如下：

```php
Co::set([
    'socket_timeout' => 5,
    'socket_connect_timeout' => 1,
    'socket_read_timeout' => 1,
    'socket_write_timeout' => 1,
]);
```

+ `-1`：表示永不超时
+ `0`：表示不更改超时时间
+ `其它大于0的值`：表示设置相应秒数的超时定时器，最大精度为`1毫秒`，是浮点型，`0.5`代表`500毫秒`
+ `socket_connect_timeout`：表示建立TCP连接超时时间，**默认为`1秒`** ，从`v4.5.x`版本开始**默认为`2秒`**
+ `socket_timeout`：表示TCP读/写操作超时时间，**默认为`-1`** ，从`v4.5.x`版本开始**默认为`60秒`** 。如果想把读和写分开设置，参考下面的配置
+ `socket_read_timeout`：`v4.3`版本加入，表示TCP**读**操作超时时间，**默认为`-1`** ，从`v4.5.x`版本开始**默认为`60秒`**
+ `socket_write_timeout`：`v4.3`版本加入，表示TCP**写**操作超时时间，**默认为`-1`** ，从`v4.5.x`版本开始**默认为`60秒`**

!> **即：** `v4.5.x`之前的版本所有`Swoole`提供的协程客户端，如果没用前面的第`1`、`2`种方式设置超时，默认连接超时时间为`1s`，读/写操作则永不超时；  
从`v4.5.x`版本开始默认连接超时时间为`60秒`，读/写操作超时时间为`60秒`；  
如果中途修改了全局超时，对于已创建的socket是不生效的。

### PHP官方网络库超时

除了上述`Swoole`提供的协程客户端，在[一键协程化](/runtime)里面使用的是原生PHP提供的方法，它们的超时时间受 [default_socket_timeout](http://php.net/manual/zh/filesystem.configuration.php) 配置影响，开发者可以通过`ini_set('default_socket_timeout', 60)`这样来单独设置它，它的默认值是60。
