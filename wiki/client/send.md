swoole_client->send发送数据
-----
与远程Server建立连接后，可向Server发送数据。函数原型：
```php
int $swoole_client->send(string $data);
```

参数为字符串，支持二进制数据。  
* 成功发送返回的已发数据长度  
* 失败返回**false**，并设置$swoole_client->errCode

