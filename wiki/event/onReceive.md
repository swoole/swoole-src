onReceive
-----
接收到数据时回调此函数，发生在worker进程中。函数原型：
```php
void onReceive(resource $server, int $fd, int $from_id, string $data);
```

swoole只负责底层通信，数据的格式，解包打包，包完整性检测需要放在应用层处理。
> onReceive回调函数收到的数据最大为8192，可以修改swoole_config.h中SW_BUFFER_SIZE宏来调整  
> Swoole支持二进制格式，$data可能是二进制数据

onReceive到的数据，需要检查是不是完整的包，是否需要继续等待数据。代码中可以增加一个 $buffer = array()，使用$fd作为key，来保存上下文数据。  
默认情况下，同一个fd会被分配到同一个worker中，所以数据可以拼接起来。使用dispatch_mode = 3时。  
请求数据是抢占式的，同一个fd发来的数据可能会被分到不同的进程。

关于粘包问题，如SMTP协议，客户端可能会同时发出2条指令。在swoole中可能是一次性收到的，这时应用层需要自行拆包。smtp是通过\r\n来分包的，所以业务代码中需要 explode("\r\n", $data)来拆分数据包。