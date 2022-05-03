# 错误码

可使用`swoole_last_error()`获取当前的错误码；

可使用`swoole_strerror(int $errno, 9);`将`Swoole`底层错误码转换成文字错误信息；

```php
echo swoole_strerror(swoole_last_error(), 9) . PHP_EOL;
echo swoole_strerror(SWOOLE_ERROR_MALLOC_FAIL, 9) . PHP_EOL;
```

## Linux错误码列表 :id=linux

| C Name          | Value | Description                                  | 含义                           |
| --------------- | ----- | -------------------------------------------- | ------------------------------ |
| Success         | 0     | Success                                      | 成功                           |
| EPERM           | 1     | Operation not permitted                      | 操作不允许                     |
| ENOENT          | 2     | No such file or directory                    | 没有这样的文件或目录           |
| ESRCH           | 3     | No such process                              | 没有这样的过程                 |
| EINTR           | 4     | Interrupted system call                      | 系统调用被中断                 |
| EIO             | 5     | I/O error                                    | I/O 错误                       |
| ENXIO           | 6     | No such device or address                    | 没有这样的设备或地址           |
| E2BIG           | 7     | Arg list too long                            | 参数列表太长                   |
| ENOEXEC         | 8     | Exec format error                            | 执行格式错误                   |
| EBADF           | 9     | Bad file number                              | 坏的文件描述符                 |
| ECHILD          | 10    | No child processes                           | 没有子进程                     |
| EAGAIN          | 11    | Try again                                    | 资源暂时不可用                 |
| ENOMEM          | 12    | Out of memory                                | 内存溢出                       |
| EACCES          | 13    | Permission denied                            | 拒绝许可                       |
| EFAULT          | 14    | Bad address                                  | 错误的地址                     |
| ENOTBLK         | 15    | Block device required                        | 块设备请求                     |
| EBUSY           | 16    | Device or resource busy                      | 设备或资源忙                   |
| EEXIST          | 17    | File exists                                  | 文件存在                       |
| EXDEV           | 18    | Cross-device link                            | 无效的交叉链接                 |
| ENODEV          | 19    | No such device                               | 设备不存在                     |
| ENOTDIR         | 20    | Not a directory                              | 不是一个目录                   |
| EISDIR          | 21    | Is a directory                               | 是一个目录                     |
| EINVAL          | 22    | Invalid argument                             | 无效的参数                     |
| ENFILE          | 23    | File table overflow                          | 打开太多的文件系统             |
| EMFILE          | 24    | Too many open files                          | 打开的文件过多                 |
| ENOTTY          | 25    | Not a tty device                             | 不是 tty 设备                  |
| ETXTBSY         | 26    | Text file busy                               | 文本文件忙                     |
| EFBIG           | 27    | File too large                               | 文件太大                       |
| ENOSPC          | 28    | No space left on device                      | 设备上没有空间                 |
| ESPIPE          | 29    | Illegal seek                                 | 非法移位                       |
| EROFS           | 30    | Read-only file system                        | 只读文件系统                   |
| EMLINK          | 31    | Too many links                               | 太多的链接                     |
| EPIPE           | 32    | Broken pipe                                  | 管道破裂                       |
| EDOM            | 33    | Math argument out of domain                  | 数值结果超出范围               |
| ERANGE          | 34    | Math result not representable                | 数值结果不具代表性             |
| EDEADLK         | 35    | Resource deadlock would occur                | 资源死锁错误                   |
| ENAMETOOLONG    | 36    | Filename too long                            | 文件名太长                     |
| ENOLCK          | 37    | No record locks available                    | 没有可用锁                     |
| ENOSYS          | 38    | Function not implemented                     | 功能没有实现                   |
| ENOTEMPTY       | 39    | Directory not empty                          | 目录不空                       |
| ELOOP           | 40    | Too many symbolic links encountered          | 符号链接层次太多               |
| EWOULDBLOCK     | 41    | Same as EAGAIN                               | 和 EAGAIN 一样                 |
| ENOMSG          | 42    | No message of desired type                   | 没有期望类型的消息             |
| EIDRM           | 43    | Identifier removed                           | 标识符删除                     |
| ECHRNG          | 44    | Channel number out of range                  | 频道数目超出范围               |
| EL2NSYNC        | 45    | Level 2 not synchronized                     | 2 级不同步                     |
| EL3HLT          | 46    | Level 3 halted                               | 3 级中断                       |
| EL3RST          | 47    | Level 3 reset                                | 3 级复位                       |
| ELNRNG          | 48    | Link number out of range                     | 链接数超出范围                 |
| EUNATCH         | 49    | Protocol driver not attached                 | 协议驱动程序没有连接           |
| ENOCSI          | 50    | No CSI structure available                   | 没有可用 CSI 结构              |
| EL2HLT          | 51    | Level 2 halted                               | 2 级中断                       |
| EBADE           | 52    | Invalid exchange                             | 无效的交换                     |
| EBADR           | 53    | Invalid request descriptor                   | 请求描述符无效                 |
| EXFULL          | 54    | Exchange full                                | 交换全                         |
| ENOANO          | 55    | No anode                                     | 没有阳极                       |
| EBADRQC         | 56    | Invalid request code                         | 无效的请求代码                 |
| EBADSLT         | 57    | Invalid slot                                 | 无效的槽                       |
| EDEADLOCK       | 58    | Same as EDEADLK                              | 和 EDEADLK 一样                |
| EBFONT          | 59    | Bad font file format                         | 错误的字体文件格式             |
| ENOSTR          | 60    | Device not a stream                          | 设备不是字符流                 |
| ENODATA         | 61    | No data available                            | 无可用数据                     |
| ETIME           | 62    | Timer expired                                | 计时器过期                     |
| ENOSR           | 63    | Out of streams resources                     | 流资源溢出                     |
| ENONET          | 64    | Machine is not on the network                | 机器不上网                     |
| ENOPKG          | 65    | Package not installed                        | 没有安装软件包                 |
| EREMOTE         | 66    | Object is remote                             | 对象是远程的                   |
| ENOLINK         | 67    | Link has been severed                        | 联系被切断                     |
| EADV            | 68    | Advertise error                              | 广告的错误                     |
| ESRMNT          | 69    | Srmount error                                | srmount 错误                   |
| ECOMM           | 70    | Communication error on send                  | 发送时的通讯错误               |
| EPROTO          | 71    | Protocol error                               | 协议错误                       |
| EMULTIHOP       | 72    | Multihop attempted                           | 多跳尝试                       |
| EDOTDOT         | 73    | RFS specific error                           | RFS 特定的错误                 |
| EBADMSG         | 74    | Not a data message                           | 非数据消息                     |
| EOVERFLOW       | 75    | Value too large for defined data type        | 值太大,对于定义数据类型        |
| ENOTUNIQ        | 76    | Name not unique on network                   | 名不是唯一的网络               |
| EBADFD          | 77    | File descriptor in bad state                 | 文件描述符在坏状态             |
| EREMCHG         | 78    | Remote address changed                       | 远程地址改变了                 |
| ELIBACC         | 79    | Cannot access a needed shared library        | 无法访问必要的共享库           |
| ELIBBAD         | 80    | Accessing a corrupted shared library         | 访问损坏的共享库               |
| ELIBSCN         | 81    | A .lib section in an .out is corrupted       | 库段. out 损坏                 |
| ELIBMAX         | 82    | Linking in too many shared libraries         | 试图链接太多的共享库           |
| ELIBEXEC        | 83    | Cannot exec a shared library directly        | 不能直接执行一个共享库         |
| EILSEQ          | 84    | Illegal byte sequence                        | 无效的或不完整的多字节或宽字符 |
| ERESTART        | 85    | Interrupted system call should be restarted  | 应该重新启动中断的系统调用     |
| ESTRPIPE        | 86    | Streams pipe error                           | 流管错误                       |
| EUSERS          | 87    | Too many users                               | 用户太多                       |
| ENOTSOCK        | 88    | Socket operation on non-socket               | 套接字操作在非套接字上         |
| EDESTADDRREQ    | 89    | Destination address required                 | 需要目标地址                   |
| EMSGSIZE        | 90    | Message too long                             | 消息太长                       |
| EPROTOTYPE      | 91    | Protocol wrong type for socket               | socket 协议类型错误            |
| ENOPROTOOPT     | 92    | Protocol not available                       | 协议不可用                     |
| EPROTONOSUPPORT | 93    | Protocol not supported                       | 不支持的协议                   |
| ESOCKTNOSUPPORT | 94    | Socket type not supported                    | 套接字类型不受支持             |
| EOPNOTSUPP      | 95    | Operation not supported on transport         | 不支持的操作                   |
| EPFNOSUPPORT    | 96    | Protocol family not supported                | 不支持的协议族                 |
| EAFNOSUPPORT    | 97    | Address family not supported by protocol     | 协议不支持的地址               |
| EADDRINUSE      | 98    | Address already in use                       | 地址已在使用                   |
| EADDRNOTAVAIL   | 99    | Cannot assign requested address              | 无法分配请求的地址             |
| ENETDOWN        | 100   | Network is down                              | 网络瘫痪                       |
| ENETUNREACH     | 101   | Network is unreachable                       | 网络不可达                     |
| ENETRESET       | 102   | Network dropped                              | 网络连接丢失                   |
| ECONNABORTED    | 103   | Software caused connection                   | 软件导致连接中断               |
| ECONNRESET      | 104   | Connection reset by                          | 连接被重置                     |
| ENOBUFS         | 105   | No buffer space available                    | 没有可用的缓冲空间             |
| EISCONN         | 106   | Transport endpoint is already connected      | 传输端点已经连接               |
| ENOTCONN        | 107   | Transport endpoint is not connected          | 传输终点没有连接               |
| ESHUTDOWN       | 108   | Cannot send after transport endpoint shutdown| 传输后无法发送                 |
| ETOOMANYREFS    | 109   | Too many references: cannot splice           | 太多的参考                     |
| ETIMEDOUT       | 110   | Connection timed                             | 连接超时                       |
| ECONNREFUSED    | 111   | Connection refused                           | 拒绝连接                       |
| EHOSTDOWN       | 112   | Host is down                                 | 主机已关闭                     |
| EHOSTUNREACH    | 113   | No route to host                             | 没有主机的路由                 |
| EALREADY        | 114   | Operation already                            | 已运行                         |
| EINPROGRESS     | 115   | Operation now in                             | 正在运行                       |
| ESTALE          | 116   | Stale NFS file handle                        | 陈旧的 NFS 文件句柄            |
| EUCLEAN         | 117   | Structure needs cleaning                     | 结构需要清洗                   |
| ENOTNAM         | 118   | Not a XENIX-named                            | 不是 XENIX 命名的              |
| ENAVAIL         | 119   | No XENIX semaphores                          | 没有 XENIX 信号量              |
| EISNAM          | 120   | Is a named type file                         | 是一个命名的文件类型           |
| EREMOTEIO       | 121   | Remote I/O error                             | 远程输入/输出错误              |
| EDQUOT          | 122   | Quota exceeded                               | 超出磁盘配额                   |
| ENOMEDIUM       | 123   | No medium found                              | 没有磁盘被发现                 |
| EMEDIUMTYPE     | 124   | Wrong medium type                            | 错误的媒体类型                 |
| ECANCELED       | 125   | Operation Canceled                           | 取消操作                       |
| ENOKEY          | 126   | Required key not available                   | 所需键不可用                   |
| EKEYEXPIRED     | 127   | Key has expired                              | 关键已过期                     |
| EKEYREVOKED     | 128   | Key has been revoked                         | 关键被撤销                     |
| EKEYREJECTED    | 129   | Key was rejected by service                  | 关键被拒绝服务                 |
| EOWNERDEAD      | 130   | Owner died                                   | 所有者死亡                     |
| ENOTRECOVERABLE | 131   | State not recoverable                        | 状态不可恢复                   |
| ERFKILL         | 132   | Operation not possible due to RF-kill        | 由于 RF-kill 而无法操作        |
| EHWPOISON       | 133   | Memory page has hardware error               | 分页硬件错误                   |

## Swoole错误码列表 :id=swoole

| Constants Name                                 | Value | Description                       |
| ---------------------------------------------- |-------|-----------------------------------|
| SWOOLE_ERROR_MALLOC_FAIL                       | 501   | Malloc fail                       |
| SWOOLE_ERROR_SYSTEM_CALL_FAIL                  | 502   | System call fail                  |
| SWOOLE_ERROR_PHP_FATAL_ERROR                   | 503   | PHP fatal error                   |
| SWOOLE_ERROR_NAME_TOO_LONG                     | 504   | Name too long                     |
| SWOOLE_ERROR_INVALID_PARAMS                    | 505   | Invalid params                    |
| SWOOLE_ERROR_QUEUE_FULL                        | 506   | Queue full                        |
| SWOOLE_ERROR_OPERATION_NOT_SUPPORT             | 507   | Operation not support             |
| SWOOLE_ERROR_PROTOCOL_ERROR                    | 508   | Protocol error                    |
| SWOOLE_ERROR_WRONG_OPERATION                   | 509   | Wrong operation                   |
| -                                              |       |                                   |
| SWOOLE_ERROR_FILE_NOT_EXIST                    | 700   | File not exist                    |
| SWOOLE_ERROR_FILE_TOO_LARGE                    | 701   | File too large                    |
| SWOOLE_ERROR_FILE_EMPTY                        | 702   | File empty                        |
| SWOOLE_ERROR_DNSLOOKUP_DUPLICATE_REQUEST       | 710   | DNS Lookup duplicate request      |
| SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED          | 711   | DNS Lookup resolve failed         |
| SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT         | 712   | DNS Lookup resolve timeout        |
| SWOOLE_ERROR_DNSLOOKUP_UNSUPPORTED             | 713   | DNS Lookup unsupported            |
| SWOOLE_ERROR_DNSLOOKUP_NO_SERVER               | 714   | DNS Lookup no server              |
| SWOOLE_ERROR_BAD_IPV6_ADDRESS                  | 720   | Bad ipv6 address                  |
| SWOOLE_ERROR_UNREGISTERED_SIGNAL               | 721   | Unregistered signal               |
| -                                              |       |                                   |
| SWOOLE_ERROR_EVENT_SOCKET_REMOVED              | 800   | Event socket removed              |
| -                                              |       |                                   |
| SWOOLE_ERROR_SESSION_CLOSED_BY_SERVER          | 1001  | Session closed by server          |
| SWOOLE_ERROR_SESSION_CLOSED_BY_CLIENT          | 1002  | Session closed by client          |
| SWOOLE_ERROR_SESSION_CLOSING                   | 1003  | Session closing                   |
| SWOOLE_ERROR_SESSION_CLOSED                    | 1004  | Session closed                    |
| SWOOLE_ERROR_SESSION_NOT_EXIST                 | 1005  | Session not exist                 |
| SWOOLE_ERROR_SESSION_INVALID_ID                | 1006  | Session invalid id                |
| SWOOLE_ERROR_SESSION_DISCARD_TIMEOUT_DATA      | 1007  | Session discard timeout data      |
| SWOOLE_ERROR_SESSION_DISCARD_DATA              | 1008  | Session discard data              |
| SWOOLE_ERROR_OUTPUT_BUFFER_OVERFLOW            | 1009  | Output buffer overflow            |
| SWOOLE_ERROR_OUTPUT_SEND_YIELD                 | 1010  | Output send yield                 |
| SWOOLE_ERROR_SSL_NOT_READY                     | 1011  | SSL not ready                     |
| SWOOLE_ERROR_SSL_CANNOT_USE_SENFILE            | 1012  | SSL cannot use senfile            |
| SWOOLE_ERROR_SSL_EMPTY_PEER_CERTIFICATE        | 1013  | SSL empty peer certificate        |
| SWOOLE_ERROR_SSL_VERIFY_FAILED                 | 1014  | SSL verify failed                 |
| SWOOLE_ERROR_SSL_BAD_CLIENT                    | 1015  | SSL bad client                    |
| SWOOLE_ERROR_SSL_BAD_PROTOCOL                  | 1016  | SSL bad protocol                  |
| SWOOLE_ERROR_SSL_RESET                         | 1017  | SSL reset                         |
| SWOOLE_ERROR_SSL_HANDSHAKE_FAILED              | 1018  | SSL handshake failed              |
| -                                              |       |                                   |
| SWOOLE_ERROR_PACKAGE_LENGTH_TOO_LARGE          | 1201  | Package length too large          |
| SWOOLE_ERROR_PACKAGE_LENGTH_NOT_FOUND          | 1202  | Package length not found          |
| SWOOLE_ERROR_DATA_LENGTH_TOO_LARGE             | 1203  | Data length too large             |
| -                                              |       |                                   |
| SWOOLE_ERROR_TASK_PACKAGE_TOO_BIG              | 2001  | Task package too big              |
| SWOOLE_ERROR_TASK_DISPATCH_FAIL                | 2002  | Task dispatch fail                |
| SWOOLE_ERROR_TASK_TIMEOUT                      | 2003  | Task timeout                      |
| -                                              |       |                                   |
| SWOOLE_ERROR_HTTP2_STREAM_ID_TOO_BIG           | 3001  | Http2 stream id too big           |
| SWOOLE_ERROR_HTTP2_STREAM_NO_HEADER            | 3002  | Http2 stream no header            |
| SWOOLE_ERROR_HTTP2_STREAM_NOT_FOUND            | 3003  | Http2 stream not found            |
| SWOOLE_ERROR_HTTP2_STREAM_IGNORE               | 3004  | Http2 stream ignore               |
| SWOOLE_ERROR_HTTP2_SEND_CONTROL_FRAME_FAILED   | 3005  | Http2 send control frame failed   |
| -                                              |       |                                   |
| SWOOLE_ERROR_AIO_BAD_REQUEST                   | 4001  | Aio bad request                   |
| SWOOLE_ERROR_AIO_CANCELED                      | 4002  | Aio canceled                      |
| SWOOLE_ERROR_AIO_TIMEOUT                       | 4003  | Aio timeout                       |
| -                                              |       |                                   |
| SWOOLE_ERROR_CLIENT_NO_CONNECTION              | 5001  | Client no connection              |
| -                                              |       |                                   |
| SWOOLE_ERROR_SOCKET_CLOSED                     | 6001  | Socket closed                     |
| SWOOLE_ERROR_SOCKET_POLL_TIMEOUT               | 6002  | Socket poll timeout               |
| -                                              |       |                                   |
| SWOOLE_ERROR_SOCKS5_UNSUPPORT_VERSION          | 7001  | Socks5 unsupport version          |
| SWOOLE_ERROR_SOCKS5_UNSUPPORT_METHOD           | 7002  | Socks5 unsupport method           |
| SWOOLE_ERROR_SOCKS5_AUTH_FAILED                | 7003  | Socks5 auth failed                |
| SWOOLE_ERROR_SOCKS5_SERVER_ERROR               | 7004  | Socks5 server error               |
| SWOOLE_ERROR_SOCKS5_HANDSHAKE_FAILED           | 7005  | Socks5 handshake failed           |
| -                                              |       |                                   |
| SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_ERROR        | 7101  | Http proxy handshake error        |
| SWOOLE_ERROR_HTTP_INVALID_PROTOCOL             | 7102  | Http invalid protocol             |
| SWOOLE_ERROR_HTTP_PROXY_HANDSHAKE_FAILED       | 7103  | Http proxy handshake failed       |
| SWOOLE_ERROR_HTTP_PROXY_BAD_RESPONSE           | 7104  | Http proxy bad response           |
| -                                              |       |                                   |
| SWOOLE_ERROR_WEBSOCKET_BAD_CLIENT              | 8501  | Websocket bad client              |
| SWOOLE_ERROR_WEBSOCKET_BAD_OPCODE              | 8502  | Websocket bad opcode              |
| SWOOLE_ERROR_WEBSOCKET_UNCONNECTED             | 8503  | Websocket unconnected             |
| SWOOLE_ERROR_WEBSOCKET_HANDSHAKE_FAILED        | 8504  | Websocket handshake failed        |
| SWOOLE_ERROR_WEBSOCKET_PACK_FAILED             | 8505  | Websocket pack failed             |
| -                                              |       |                                   |
| SWOOLE_ERROR_SERVER_MUST_CREATED_BEFORE_CLIENT | 9001  | Server must created before client |
| SWOOLE_ERROR_SERVER_TOO_MANY_SOCKET            | 9002  | Server too many socket            |
| SWOOLE_ERROR_SERVER_WORKER_TERMINATED          | 9003  | Server worker terminated          |
| SWOOLE_ERROR_SERVER_INVALID_LISTEN_PORT        | 9004  | Server invalid listen port        |
| SWOOLE_ERROR_SERVER_TOO_MANY_LISTEN_PORT       | 9005  | Server too many listen port       |
| SWOOLE_ERROR_SERVER_PIPE_BUFFER_FULL           | 9006  | Server pipe buffer full           |
| SWOOLE_ERROR_SERVER_NO_IDLE_WORKER             | 9007  | Server no idle worker             |
| SWOOLE_ERROR_SERVER_ONLY_START_ONE             | 9008  | Server only start one             |
| SWOOLE_ERROR_SERVER_SEND_IN_MASTER             | 9009  | Server send in master             |
| SWOOLE_ERROR_SERVER_INVALID_REQUEST            | 9010  | Server invalid request            |
| SWOOLE_ERROR_SERVER_CONNECT_FAIL               | 9011  | Server connect fail               |
| SWOOLE_ERROR_SERVER_INVALID_COMMAND            | 9012  | Server invalid command            |
| SWOOLE_ERROR_SERVER_IS_NOT_REGULAR_FILE        | 9013  | Server is not regular file        |
| -                                              |       |                                   |
| SWOOLE_ERROR_SERVER_WORKER_EXIT_TIMEOUT        | 9101  | Server worker exit timeout        |
| SWOOLE_ERROR_SERVER_WORKER_ABNORMAL_PIPE_DATA  | 9102  | Server worker abnormal pipe data  |
| SWOOLE_ERROR_SERVER_WORKER_UNPROCESSED_DATA    | 9103  | Server worker unprocessed data    |
| -                                              |       |                                   |
| SWOOLE_ERROR_CO_OUT_OF_COROUTINE               | 10001 | Coroutine out of coroutine        |
| SWOOLE_ERROR_CO_HAS_BEEN_BOUND                 | 10002 | Coroutine has been bound          |
| SWOOLE_ERROR_CO_HAS_BEEN_DISCARDED             | 10003 | Coroutine has been discarded      |
| SWOOLE_ERROR_CO_MUTEX_DOUBLE_UNLOCK            | 10004 | Coroutine mutex double unlock     |
| SWOOLE_ERROR_CO_BLOCK_OBJECT_LOCKED            | 10005 | Coroutine block object locked     |
| SWOOLE_ERROR_CO_BLOCK_OBJECT_WAITING           | 10006 | Coroutine block object waiting    |
| SWOOLE_ERROR_CO_YIELD_FAILED                   | 10007 | Coroutine yield failed            |
| SWOOLE_ERROR_CO_GETCONTEXT_FAILED              | 10008 | Coroutine getcontext failed       |
| SWOOLE_ERROR_CO_SWAPCONTEXT_FAILED             | 10009 | Coroutine swapcontext failed      |
| SWOOLE_ERROR_CO_MAKECONTEXT_FAILED             | 10010 | Coroutine makecontext failed      |
| SWOOLE_ERROR_CO_IOCPINIT_FAILED                | 10011 | Coroutine iocpinit failed         |
| SWOOLE_ERROR_CO_PROTECT_STACK_FAILED           | 10012 | Coroutine protect stack failed    |
| SWOOLE_ERROR_CO_STD_THREAD_LINK_ERROR          | 10013 | Coroutine std thread link error   |
| SWOOLE_ERROR_CO_DISABLED_MULTI_THREAD          | 10014 | Coroutine disabled multi thread   |
| SWOOLE_ERROR_CO_CANNOT_CANCEL                  | 10015 | Coroutine cannot cancel           |
| SWOOLE_ERROR_CO_NOT_EXISTS                     | 10016 | Coroutine not exists              |
