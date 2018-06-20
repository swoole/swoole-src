/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/
#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#ifndef __clang__
//gcc version check
#if defined(__GNUC__) && (__GNUC__ < 3 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4))
#error "GCC 4.4 or later required."
#endif
#endif

#define SW_COROUTINE               1

#define SW_MAX_FDTYPE              32   //32 kinds of event
#define SW_MAX_HOOK_TYPE           32
#define SW_ERROR_MSG_SIZE          512
#define SW_MAX_FILE_CONTENT        (64*1024*1024) //for swoole_file_get_contents
#define SW_MAX_LISTEN_PORT         60000
#define SW_MAX_CONCURRENT_TASK     1024

#ifdef HAVE_MALLOC_TRIM
#define SW_USE_MALLOC_TRIM
#endif

#define SW_MALLOC_TRIM_INTERVAL    1
#define SW_MALLOC_TRIM_PAD         0
#define SW_USE_EVENT_TIMER
#define SW_USE_MONOTONIC_TIME
//#define SW_USE_RINGBUFFER

//#define SW_USE_TIMEWHEEL
#define SW_TIMEWHEEL_SIZE          60

//#define SW_DEBUG_REMOTE_OPEN
#define SW_DEBUG_SERVER_HOST       "127.0.0.1"
#define SW_DEBUG_SERVER_PORT       9999

#define SW_DEBUG_SERVER_DESTRUCT   0

#define SW_SOCKET_OVERFLOW_WAIT    100
#define SW_SOCKET_MAX_DEFAULT      65536
#define SW_SOCKET_BUFFER_SIZE      (8*1024*1024)
#define SW_SYSTEMD_FDS_START       3

#define SW_GLOBAL_MEMORY_PAGESIZE  (1024*1024*2) //全局内存的分页

#define SW_MAX_THREAD_NCPU         4 // n * cpu_num
#define SW_MAX_WORKER_NCPU         1000 // n * cpu_num
#define SW_MAX_REQUEST             5000          //最大请求包数

#define SW_CORO_SCHEDUER_TIMEOUT   100           //协程强制超时回调的单位时间 100ms
//#define SW_CONNECTION_LIST_EXPAND  (4096*2)  //动态扩容的数量

#define SW_HOST_MAXSIZE            104  // Linux has 108 UNIX_PATH_MAX, but BSD/MacOS limit is only 104

//#define SW_DEBUG                 //debug
#define SW_LOG_NO_SRCINFO          //no source info
//#define SW_BUFFER_SIZE           65495 //65535 - 28 - 12(UDP最大包 - 包头 - 3个INT)
#define SW_CLIENT_BUFFER_SIZE      65536
//#define SW_CLIENT_RECV_AGAIN
#define SW_CLIENT_DEFAULT_TIMEOUT  0.5
#define SW_CLIENT_MAX_PORT         65535
//#define SW_CLIENT_SOCKET_WAIT

//!!!Don't modify.----------------------------------------------------------
#if __MACH__
#define SW_IPC_MAX_SIZE            2048  //MacOS
#else
#define SW_IPC_MAX_SIZE            8192  //for IPC, dgram and message-queue max size
#endif

#ifdef SW_USE_RINGBUFFER
#define SW_BUFFER_SIZE             65535
#else
#define SW_BUFFER_SIZE             (SW_IPC_MAX_SIZE - sizeof(struct _swDataHead))
#endif
//!!!End.-------------------------------------------------------------------

#define SW_BUFFER_SIZE_STD         8192
#define SW_BUFFER_SIZE_BIG         65536
#define SW_BUFFER_SIZE_UDP         65536
//#define SW_BUFFER_RECV_TIME
#define SW_SENDFILE_CHUNK_SIZE     65536

#define SW_SENDFILE_MAXLEN         4194304

#define SW_HASHMAP_KEY_MAXLEN      256
#define SW_HASHMAP_INIT_BUCKET_N   32  //hashmap初始化时创建32大小的桶

#define SW_DATA_EOF                "\r\n\r\n"
#define SW_DATA_EOF_MAXLEN         8

#define SW_TASKWAIT_TIMEOUT        0.5

#define SW_AIO_THREAD_NUM_DEFAULT        2
#define SW_AIO_THREAD_NUM_MAX            32
#define SW_AIO_MAX_FILESIZE              4194304  //4M
#define SW_AIO_EVENT_NUM                 128
#define SW_AIO_DEFAULT_CHUNK_SIZE        65536
#define SW_AIO_MAX_CHUNK_SIZE            1*1024*1024
//#define SW_AIO_THREAD_USE_CHANNEL
#define SW_AIO_MAX_EVENTS                128
#define SW_AIO_HANDLER_MAX_SIZE          8
//#define SW_THREADPOOL_USE_CHANNEL
#define SW_THREADPOOL_QUEUE_LEN          10000
#define SW_IP_MAX_LENGTH                 32

//#define SW_USE_SOCKET_LINGER

#define SW_WORKER_WAIT_TIMEOUT     1000
//#define SW_WORKER_RECV_AGAIN

#define SW_WORKER_USE_SIGNALFD
#define SW_WORKER_MAX_WAIT_TIME          30           //最大等待时间

//#define SW_WORKER_SEND_CHUNK

#define SW_REACTOR_SCHEDULE              2
#define SW_REACTOR_MAXEVENTS             4096
#define SW_REACTOR_USE_SESSION
#define SW_SESSION_LIST_SIZE             (1024*1024)

#define SW_MSGMAX                        65536

/**
 * 最大Reactor线程数量，默认会启动CPU核数的线程数
 * 如果超过8核，默认启动8个线程
 */
#define SW_REACTOR_MAX_THREAD            8

/**
 * 循环从管道中读取数据，有助于缓解管道缓存塞满问题，降低进程间通信的压力
 */
#define SW_REACTOR_RECV_AGAIN
#define SW_REACTOR_SYNC_SEND            //direct send

#define SW_RINGQUEUE_LEN                 1024           //RingQueue队列长度

//#define SW_USE_RINGQUEUE_TS            1     //使用线程安全版本的RingQueue
#define SW_RINGBUFFER_FREE_N_MAX         4     //when free_n > MAX, execute collect
#define SW_RINGBUFFER_WARNING            100
//#define SW_RINGBUFFER_DEBUG

/**
 * ringbuffer memory pool size
 */
#define SW_BUFFER_OUTPUT_SIZE            (1024*1024*2)
#define SW_BUFFER_INPUT_SIZE             (1024*1024*2)
#define SW_BUFFER_MIN_SIZE               65536
#define SW_PIPE_BUFFER_SIZE              (1024*1024*32)

#define SW_BACKLOG                       512

/**
 * 是否循环accept，可以一次性处理完全部的listen队列，用于大量并发连接的场景
 */
#define SW_ACCEPT_AGAIN                  1

/**
 * 一次循环的最大accept次数
 */
#define SW_ACCEPT_MAX_COUNT              64

#define SW_TCP_KEEPCOUNT                 5
#define SW_TCP_KEEPIDLE                  3600 //1 hour
#define SW_TCP_KEEPINTERVAL              60

#define SW_USE_EVENTFD                   //是否使用eventfd来做消息通知，需要Linux 2.6.22以上版本才会支持

#define SW_TASK_TMP_FILE                 "/tmp/swoole.task.XXXXXX"
#define SW_TASK_TMPDIR_SIZE              128

#define SW_FILE_CHUNK_SIZE               65536

#define SW_TABLE_CONFLICT_PROPORTION     0.2 //20%
#define SW_TABLE_KEY_SIZE                64
//#define SW_TABLE_USE_PHP_HASH
//#define SW_TABLE_DEBUG
#define SW_TABLE_USE_SPINLOCK            1

#define SW_SSL_BUFFER_SIZE               16384
#define SW_SSL_CIPHER_LIST               "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
#define SW_SSL_ECDH_CURVE                "secp384r1"
#define SW_SSL_NPN_ADVERTISE             "\x08http/1.1"
#define SW_SSL_HTTP2_NPN_ADVERTISE       "\x02h2"

#define SW_SPINLOCK_LOOP_N               1024

#define SW_STRING_BUFFER_MAXLEN          (1024*1024*128)
#define SW_STRING_BUFFER_DEFAULT         128
#define SW_STRING_BUFFER_GARBAGE_MIN     (1024*64)
#define SW_STRING_BUFFER_GARBAGE_RATIO   4

#define SW_SIGNO_MAX                     128

#define SW_DNS_HOST_BUFFER_SIZE          16
#define SW_DNS_SERVER_PORT               53
#define SW_DNS_DEFAULT_SERVER            "8.8.8.8"

/**
 * HTTP Protocol
 */
#define SW_HTTP_SERVER_SOFTWARE          "swoole-http-server"
#define SW_HTTP_BAD_REQUEST              "<h1>400 Bad Request</h1>\r\n"
#define SW_HTTP_PARAM_MAX_NUM            128
#define SW_HTTP_COOKIE_KEYLEN            128
#define SW_HTTP_COOKIE_VALLEN            4096
#define SW_HTTP_RESPONSE_INIT_SIZE       65536
#define SW_HTTP_HEADER_MAX_SIZE          8192
#define SW_HTTP_HEADER_KEY_SIZE          128
#define SW_HTTP_HEADER_VALUE_SIZE        4096
#define SW_HTTP_HEADER_BUFFER_SIZE       128
#define SW_HTTP_COMPRESS_GZIP
#define SW_HTTP_UPLOAD_TMPDIR_SIZE       256
#define SW_HTTP_DATE_FORMAT              "D, d M Y H:i:s T"
#define SW_HTTP_RFC1123_DATE_GMT         "%a, %d %b %Y %T GMT"
#define SW_HTTP_RFC1123_DATE_UTC         "%a, %d %b %Y %T UTC"
#define SW_HTTP_RFC850_DATE              "%A, %d-%b-%y %T GMT"
#define SW_HTTP_ASCTIME_DATE             "%a %b %e %T %Y"
//#define SW_HTTP_100_CONTINUE

/**
 * HTTP2 Protocol
 */
#define SW_HTTP2_DATA_BUFFSER_SIZE       8192
#define SW_HTTP2_MAX_CONCURRENT_STREAMS  128
#define SW_HTTP2_MAX_FRAME_SIZE          ((1u << 14))
#define SW_HTTP2_MAX_WINDOW              ((1u << 31) - 1)
#define SW_HTTP2_DEFAULT_WINDOW          65535

#define SW_HTTP_CLIENT_USERAGENT         "swoole-http-client"
#define SW_HTTP_CLIENT_BOUNDARY_PREKEY   "----SwooleBoundary"
#define SW_HTTP_FORM_DATA_FORMAT_STRING  "--%*s\r\nContent-Disposition: form-data; name=\"%*s\"\r\n\r\n"
#define SW_HTTP_FORM_DATA_FORMAT_FILE    "--%*s\r\nContent-Disposition: form-data; name=\"%*s\"; filename=\"%*s\"\r\nContent-Type: %*s\r\n\r\n"

#define SW_WEBSOCKET_SERVER_SOFTWARE     "swoole-websocket-server"
#define SW_WEBSOCKET_VERSION             "13"
#define SW_WEBSOCKET_KEY_LENGTH          16
#define SW_WEBSOCKET_QUEUE_SIZE          16

#define SW_MYSQL_QUERY_INIT_SIZE         8192
#define SW_MYSQL_DEFAULT_PORT            3306
#define SW_MYSQL_CONNECT_TIMEOUT         1.0
#define SW_MYSQL_DEFAULT_CHARSET         33  //0x21, utf8_general_ci

#define SW_REDIS_CONNECT_TIMEOUT         1.0

#define SW_TIMER_MAX_VALUE               86400000

/**
 * Coroutine
 */
#define SW_DEFAULT_MAX_CORO_NUM          3000
#define SW_DEFAULT_STACK_SIZE            8192
#define SW_DEFAULT_C_STACK_SIZE          (1024 * 1024 * 2)
#define SW_MAX_CORO_NUM_LIMIT            0x80000

#endif /* SWOOLE_CONFIG_H_ */
