swoole_client->sock
-----
类型为int。sock属性是此socket的文件描述符。在PHP代码中可以使用
```php
$sock = fopen("php://fd/".$swoole_client->sock); 
```
将swoole_client的socket转换成一个stream socket。可以调用fread/fwrite/fclose等函数进程操作。  
> swoole_server中的$fd不能用此方法转换，因为$fd只是一个数字，$fd文件描述符属于主进程  

$swoole_client->sock可以转换成int作为数组的key.

