# 其他知识

## 设置DNS解析超时和重试

网络编程中经常使用`gethostbyname`和`getaddrinfo`来实现域名解析，这两个`C`函数并未提供超时参数。实际上可以修改`/etc/resolv.conf`来设置超时和重试逻辑。

!> 可参考`man resolv.conf`文档

### 多个 NameServer <!-- {docsify-ignore} -->

```
nameserver 192.168.1.3
nameserver 192.168.1.5
option rotate
```

可配置多个`nameserver`，底层会自动轮询，在第一个`nameserver`查询失败时会自动切换为第二个`nameserver`进行重试。

`option rotate`配置的作用是，进行`nameserver`负载均衡，使用轮询模式。

### 超时控制 <!-- {docsify-ignore} -->

```
option timeout:1 attempts:2
```

* `timeout`：控制`UDP`接收的超时时间，单位为秒，默认为`5`秒
* `attempts`：控制尝试的次数，配置为`2`时表示，最多尝试`2`次，默认为`5`次

假设有`2`个`nameserver`，`attempts`为`2`，超时为`1`，那么如果所有`DNS`服务器无响应的情况下，最长等待时间为`4`秒（`2x2x1`）。

### 调用跟踪 <!-- {docsify-ignore} -->

可使用[strace](/other/tools?id=strace)跟踪确认。

将`nameserver`设置为两个不存在的`IP`，`PHP`代码使用`var_dump(gethostbyname('www.baidu.com'));`解析域名。

```
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.20.128.16")}, 16) = 0
poll([{fd=3, events=POLLOUT}], 1, 0)    = 1 ([{fd=3, revents=POLLOUT}])
sendto(3, "\346\5\1\0\0\1\0\0\0\0\0\0\3www\5baidu\3com\0\0\1\0\1", 31, MSG_NOSIGNAL, NULL, 0) = 31
poll([{fd=3, events=POLLIN}], 1, 1000

)  = 0 (Timeout)
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.20.128.18")}, 16) = 0
poll([{fd=4, events=POLLOUT}], 1, 0)    = 1 ([{fd=4, revents=POLLOUT}])
sendto(4, "\346\5\1\0\0\1\0\0\0\0\0\0\3www\5baidu\3com\0\0\1\0\1", 31, MSG_NOSIGNAL, NULL, 0) = 31
poll([{fd=4, events=POLLIN}], 1, 1000


)  = 0 (Timeout)
poll([{fd=3, events=POLLOUT}], 1, 0)    = 1 ([{fd=3, revents=POLLOUT}])
sendto(3, "\346\5\1\0\0\1\0\0\0\0\0\0\3www\5baidu\3com\0\0\1\0\1", 31, MSG_NOSIGNAL, NULL, 0) = 31
poll([{fd=3, events=POLLIN}], 1, 1000


)  = 0 (Timeout)
poll([{fd=4, events=POLLOUT}], 1, 0)    = 1 ([{fd=4, revents=POLLOUT}])
sendto(4, "\346\5\1\0\0\1\0\0\0\0\0\0\3www\5baidu\3com\0\0\1\0\1", 31, MSG_NOSIGNAL, NULL, 0) = 31
poll([{fd=4, events=POLLIN}], 1, 1000



)  = 0 (Timeout)
close(3)                                = 0
close(4)                                = 0
```

可以看到这里一共重试了`4`次，`poll`调用超时设置为`1000ms`（`1秒`）。
