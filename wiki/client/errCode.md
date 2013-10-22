swoole_client->errCode
-----
类型为int型。当connect/send/recv/close失败时，会自动设置$swoole_client->errCode的值。  
errCode的值等于Linux errno，错误信息对照表：  

> [Linux的errno定义](http://swoole.sinaapp.com/archives/110)