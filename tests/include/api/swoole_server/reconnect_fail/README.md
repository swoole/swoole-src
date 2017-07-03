## 重连失败

`swoole ver 1.1.2.1`
 
## 步骤

1. server 在onReceive回调close调client连接
2. client 在onConnect回调发送1.9M数据
3. client 在onClose回调重新连接
 
## 现象

### Mac

#### client: error 与 close 回调均不会触发

```
Reconnect
[2017-01-11 10:58:21 @15889.0]	WARNING	swReactorKqueue_wait: kqueue event unknow filter=-1
```

#### server:
    1. connection#10[session_id=1] is closed by server.
    2. [1]received the wrong data[2036 bytes] from socket#1
    3. 不断触发 onReceive回调, close(fd)方法总是返回false

```
/Users/chuxiaofeng/yz_env/php/bin/php /Users/chuxiaofeng/Documents/yz-swoole/swoole-extension/php-tests/apitest/swoole_server/reconnect_fail/tcp_serv.php
[2017-01-11 10:58:20 *15887.0]	WARNING	swServer_tcp_deny_exit: swServer_tcp_deny_exit
[2017-01-11 10:58:20 *15888.1]	WARNING	swServer_tcp_deny_exit: swServer_tcp_deny_exit
[2017-01-11 10:58:20 #15885.0]	WARNING	swReactorThread_onPipeReceive: [Master] set worker idle.[work_id=0]
[2017-01-11 10:58:20 #15885.0]	WARNING	swReactorThread_onPipeReceive: [Master] set worker idle.[work_id=1]
[15887 2017-01-11 10:58:20] worker #0 starting .....
[15888 2017-01-11 10:58:20] worker #1 starting .....
[15885 2017-01-11 10:58:20] server starting .....
close 1
close 1
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
[2017-01-11 10:58:21 #15885.0]	WARNING	swFactoryProcess_dispatch: dispatch[type=0] failed, connection#10[session_id=1] is closed by server.
bool(true)
bool(true)
close 1
[2017-01-11 10:58:21 *15887.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[2036 bytes] from socket#1
bool(false)
close 1
close 1
bool(false)
bool(false)
close 1
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
close 1
bool(false)
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
[2017-01-11 10:58:21 #15885.0]	ERROR	swReactorThread_send (ERROR 1005): send event$[4] failed, session#1 does not exist.
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
close 1
bool(false)
```

### CentOS


#### client 触发若干次close回调, 最后一次close不会触发,重连失败

```
Reconnect
close
Reconnect
close
Reconnect
close
Reconnect
close
Reconnect
close
Reconnect
```

#### server


```
[16369 2017-01-11 10:53:19] server starting .....
[2017-01-11 10:53:20 *16372.0]	WARNING	swServer_tcp_deny_exit: swServer_tcp_deny_exit
[2017-01-11 10:53:20 *16373.1]	WARNING	swServer_tcp_deny_exit: swServer_tcp_deny_exit
[16372 2017-01-11 10:53:20] worker #0 starting .....
[2017-01-11 10:53:20 #16369.0]	WARNING	swReactorThread_onPipeReceive: [Master] set worker idle.[work_id=0]
[2017-01-11 10:53:20 #16369.0]	WARNING	swReactorThread_onPipeReceive: [Master] set worker idle.[work_id=1]
[16373 2017-01-11 10:53:20] worker #1 starting .....
close 1
close 1
bool(true)
bool(false)
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#1
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[21 bytes] from socket#1
[2017-01-11 10:53:25 *16373.1]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#1
close 2
close 2
bool(true)
bool(false)
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#2
[2017-01-11 10:53:25 *16373.1]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#2
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[21 bytes] from socket#2
close 3
bool(true)
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#3
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#3
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#3
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[21 bytes] from socket#3
close 4
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4
bool(true)
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4
[2017-01-11 10:53:25 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[21 bytes] from socket#4
close 4
bool(false)
close 5
close 5
bool(true)
bool(false)


......


close 4402
bool(true)
bool(false)
[2017-01-11 10:53:29 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4402
[2017-01-11 10:53:29 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[21 bytes] from socket#4402
[2017-01-11 10:53:29 *16373.1]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4402
close 4403
close 4403
bool(false)
bool(true)
[2017-01-11 10:53:29 *16372.0]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4403
[2017-01-11 10:53:29 *16373.1]	ERROR	swWorker_discard_data (ERROR 1007): [1]received the wrong data[8180 bytes] from socket#4403
close 4403
bool(false)
```