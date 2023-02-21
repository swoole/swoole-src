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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/
#ifndef SWOOLE_CONFIG_H_
#define SWOOLE_CONFIG_H_

#ifndef __clang__
// gcc version check
#if defined(__GNUC__) && (__GNUC__ < 3 || (__GNUC__ == 4 && __GNUC_MINOR__ < 8))
#error "GCC 4.8 or later required"
#endif
#endif

#define SW_MAX_FDTYPE 32  // 32 kinds of event
#define SW_MAX_HOOK_TYPE 32
#define SW_ERROR_MSG_SIZE 16384
#define SW_MAX_FILE_CONTENT (64 * 1024 * 1024)  // for swoole_file_get_contents
#define SW_MAX_LISTEN_PORT 60000
#define SW_MAX_CONNECTION 100000
#define SW_MAX_CONCURRENT_TASK 1024
#define SW_STACK_BUFFER_SIZE 65536

#ifdef HAVE_MALLOC_TRIM
#define SW_USE_MALLOC_TRIM 1
#endif
#define SW_MALLOC_TRIM_INTERVAL 60
#define SW_MALLOC_TRIM_PAD 0
#define SW_USE_MONOTONIC_TIME 1

#define SW_MAX_SOCKETS_DEFAULT 1024

#define SW_SOCKET_OVERFLOW_WAIT 100
#define SW_SOCKET_MAX_DEFAULT 65536
#if defined(__MACH__) || defined(__FreeBSD__)
#define SW_SOCKET_BUFFER_SIZE 262144
#else
#define SW_SOCKET_BUFFER_SIZE 8388608
#endif
#define SW_SOCKET_RETRY_COUNT 10

#define SW_SOCKET_DEFAULT_DNS_TIMEOUT 60
#define SW_SOCKET_DEFAULT_CONNECT_TIMEOUT 2
#define SW_SOCKET_DEFAULT_READ_TIMEOUT 60
#define SW_SOCKET_DEFAULT_WRITE_TIMEOUT 60

#define SW_SYSTEMD_FDS_START 3

#define SW_GLOBAL_MEMORY_PAGESIZE (2 * 1024 * 1024)  // global memory page

#define SW_MAX_THREAD_NCPU 4     // n * cpu_num
#define SW_MAX_WORKER_NCPU 1000  // n * cpu_num

#define SW_HOST_MAXSIZE                                                                                                \
    sizeof(((struct sockaddr_un *) NULL)->sun_path)  // Linux has 108 UNIX_PATH_MAX, but BSD/MacOS limit is only 104

#define SW_LOG_NO_SRCINFO 1  // no source info
#define SW_CLIENT_BUFFER_SIZE 65536
#define SW_CLIENT_CONNECT_TIMEOUT 0.5
#define SW_CLIENT_MAX_PORT 65535

// !!!Don't modify.----------------------------------------------------------
#ifdef __MACH__
#define SW_IPC_MAX_SIZE 2048  // MacOS
#else
#define SW_IPC_MAX_SIZE 8192  // for IPC, dgram and message-queue max size
#endif
#define SW_IPC_BUFFER_MAX_SIZE (64 * 1024)
#define SW_IPC_BUFFER_SIZE (SW_IPC_MAX_SIZE - sizeof(swoole::DataHead))
// !!!End.-------------------------------------------------------------------

#define SW_BUFFER_SIZE_STD 8192
#define SW_BUFFER_SIZE_BIG 65536
#define SW_BUFFER_SIZE_UDP 65536

#define SW_SENDFILE_CHUNK_SIZE 65536
#define SW_SENDFILE_MAXLEN 4194304

#define SW_HASHMAP_KEY_MAXLEN 256
#define SW_HASHMAP_INIT_BUCKET_N 32  // hashmap bucket num (default value for init)

#define SW_DATA_EOF "\r\n\r\n"
#define SW_DATA_EOF_MAXLEN 8

#define SW_TASKWAIT_TIMEOUT 0.5

#define SW_AIO_THREAD_NUM_MULTIPLE 8
#define SW_AIO_THREAD_MAX_IDLE_TIME 1.0
#define SW_AIO_TASK_MAX_WAIT_TIME 0.001
#define SW_AIO_MAX_FILESIZE (4 * 1024 * 1024)
#define SW_AIO_EVENT_NUM 128
#define SW_AIO_DEFAULT_CHUNK_SIZE 65536
#define SW_AIO_MAX_CHUNK_SIZE (1 * 1024 * 1024)
#define SW_AIO_MAX_EVENTS 128
#define SW_AIO_HANDLER_MAX_SIZE 8
#define SW_THREADPOOL_QUEUE_LEN 10000
#define SW_IP_MAX_LENGTH 46

#define SW_WORKER_WAIT_TIMEOUT 1000

#define SW_WORKER_USE_SIGNALFD 1
#define SW_WORKER_MAX_WAIT_TIME 3
#define SW_WORKER_MIN_REQUEST 10
#define SW_WORKER_MAX_RECV_CHUNK_COUNT 32

#define SW_REACTOR_MAXEVENTS 4096

#define SW_SESSION_LIST_SIZE (1 * 1024 * 1024)

#define SW_MSGMAX 65536
#define SW_MESSAGE_BOX_SIZE  65536

#define SW_DGRAM_HEADER_SIZE 32

/**
 * The maximum number of Reactor threads
 * the number of the CPU cores threads will be started by default
 * number 8 is the maximum
 */
#define SW_REACTOR_MAX_THREAD 8

/**
 * Loops read data from the pipeline,
 * helping to alleviate pipeline cache congestion
 * reduce the pressure of interprocess communication
 */
#define SW_REACTOR_RECV_AGAIN 1

/**
 * RINGBUFFER
 */
#define SW_RINGQUEUE_LEN 1024
#define SW_RINGBUFFER_FREE_N_MAX 4  // when free_n > MAX, execute collect
#define SW_RINGBUFFER_WARNING 100

/**
 * ringbuffer memory pool size
 */
#define SW_OUTPUT_BUFFER_SIZE (2 * 1024 * 1024)
#define SW_INPUT_BUFFER_SIZE (2 * 1024 * 1024)
#define SW_BUFFER_MIN_SIZE 65536
#define SW_SEND_BUFFER_SIZE 65536

#define SW_BACKLOG 512

/**
 * max accept times for single time
 */
#define SW_ACCEPT_MAX_COUNT 64
#define SW_ACCEPT_RETRY_TIME 1.0

#define SW_TCP_KEEPCOUNT 5
#define SW_TCP_KEEPIDLE 3600  // 1 hour
#define SW_TCP_KEEPINTERVAL 60

#define SW_USE_EVENTFD                                                                                                 \
    1  // Whether to use eventfd for message notification, Linux 2.6.22 or later is required to support

#define SW_TASK_TMP_PATH_SIZE 256
#define SW_TASK_TMP_DIR "/tmp"
#define SW_TASK_TMP_FILE "swoole.task.XXXXXX"

#define SW_FILE_CHUNK_SIZE 65536

#define SW_TABLE_CONFLICT_PROPORTION 0.2  // 20%
#define SW_TABLE_KEY_SIZE 64

#define SW_SSL_BUFFER_SIZE 16384
#define SW_SSL_CIPHER_LIST "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
#define SW_SSL_ECDH_CURVE "auto"

#define SW_SPINLOCK_LOOP_N 1024

#define SW_STRING_BUFFER_MAXLEN (1024 * 1024 * 128)
#define SW_STRING_BUFFER_DEFAULT 128
#define SW_STRING_BUFFER_GARBAGE_MIN (1024 * 64)
#define SW_STRING_BUFFER_GARBAGE_RATIO 4

#define SW_SIGNO_MAX 128
#define SW_UNREGISTERED_SIGNAL_FMT "Unable to find callback function for signal %s"

#define SW_DNS_HOST_BUFFER_SIZE 16
#define SW_DNS_SERVER_PORT 53
#define SW_DNS_RESOLV_CONF "/etc/resolv.conf"

#define SW_Z_BEST_SPEED 1
#define SW_COMPRESSION_MIN_LENGTH_DEFAULT 20

#ifndef IOV_MAX
#define IOV_MAX 16
#endif

#define IOV_MAX_ERROR_MSG "The maximum of iov count is %d"

/**
 * HTTP Protocol
 */
#define SW_HTTP_SERVER_SOFTWARE "swoole-http-server"
#define SW_HTTP_SERVER_BOUNDARY_PREKEY "SwooleBoundary"
#define SW_HTTP_SERVER_BOUNDARY_TOTAL_SIZE 39
#define SW_HTTP_SERVER_PART_HEADER 256
#define SW_HTTP_PARAM_MAX_NUM 128
#define SW_HTTP_FORM_KEYLEN 512
#define SW_HTTP_RESPONSE_INIT_SIZE 65536
#define SW_HTTP_HEADER_MAX_SIZE 65536
#define SW_HTTP_HEADER_KEY_SIZE 128
#define SW_HTTP_UPLOAD_TMPDIR_SIZE SW_TASK_TMP_PATH_SIZE
#define SW_HTTP_DATE_FORMAT "D, d M Y H:i:s T"
#define SW_HTTP_RFC1123_DATE_GMT "%a, %d %b %Y %T GMT"
#define SW_HTTP_RFC1123_DATE_UTC "%a, %d %b %Y %T UTC"
#define SW_HTTP_RFC850_DATE "%A, %d-%b-%y %T GMT"
#define SW_HTTP_ASCTIME_DATE "%a %b %e %T %Y"
#define SW_HTTP_CHUNK_EOF "0\r\n\r\n"

// #define SW_HTTP_100_CONTINUE
#define SW_HTTP_100_CONTINUE_PACKET "HTTP/1.1 100 Continue\r\n\r\n"
#define SW_HTTP_BAD_REQUEST_PACKET "HTTP/1.1 400 Bad Request\r\n\r\n"
#define SW_HTTP_REQUEST_ENTITY_TOO_LARGE_PACKET "HTTP/1.1 413 Request Entity Too Large\r\n\r\n"
#define SW_HTTP_SERVICE_UNAVAILABLE_PACKET "HTTP/1.1 503 Service Unavailable\r\n\r\n"

#define SW_HTTP_PAGE_CSS "<style> \
body { padding: 0.5em; line-height: 2; } \
h1 { font-size: 1.5em; padding-bottom: 0.3em; border-bottom: 1px solid #ccc; } \
ul { list-style-type: disc; } \
footer { border-top: 1px solid #ccc; } \
a { color: #0969da; } \
</style>"

#define SW_HTTP_POWER_BY  "<footer><i>Powered by Swoole</i></footer>"

#define SW_HTTP_PAGE_400 "<html><body>" SW_HTTP_PAGE_CSS "<h1>HTTP 400 Bad Request</h1>" SW_HTTP_POWER_BY "</body></html>"
#define SW_HTTP_PAGE_404 "<html><body>" SW_HTTP_PAGE_CSS "<h1>HTTP 404 Not Found</h1>" SW_HTTP_POWER_BY "</body></html>"
#define SW_HTTP_PAGE_500 "<html><body>" SW_HTTP_PAGE_CSS "<h1>HTTP 500 Internal Server Error</h1>" SW_HTTP_POWER_BY "</body></html>"

/**
 * HTTP2 Protocol
 */
#define SW_HTTP2_DATA_BUFFER_SIZE 8192
#define SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)
#define SW_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 128
#define SW_HTTP2_DEFAULT_ENABLE_PUSH 0
#define SW_HTTP2_DEFAULT_MAX_FRAME_SIZE ((1u << 14))
#define SW_HTTP2_DEFAULT_INIT_WINDOW_SIZE ((1u << 31) - 1)
#define SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE UINT_MAX

#define SW_HTTP_CLIENT_USERAGENT "swoole-http-client"
#define SW_HTTP_CLIENT_BOUNDARY_PREKEY "----SwooleBoundary"
#define SW_HTTP_CLIENT_BOUNDARY_TOTAL_SIZE 39
#define SW_HTTP_FORM_RAW_DATA_FMT "--%.*s\r\nContent-Disposition: form-data; name=\"%.*s\"\r\n\r\n"
#define SW_HTTP_FORM_RAW_DATA_FMT_LEN 8
#define SW_HTTP_FORM_FILE_DATA_FMT                                                                                     \
    "--%.*s\r\nContent-Disposition: form-data; name=\"%.*s\"; filename=\"%.*s\"\r\nContent-Type: %.*s\r\n\r\n"
#define SW_HTTP_FORM_FILE_DATA_FMT_LEN 16

#define SW_WEBSOCKET_VERSION "13"
#define SW_WEBSOCKET_KEY_LENGTH 16
#define SW_WEBSOCKET_QUEUE_SIZE 16
#define SW_WEBSOCKET_EXTENSION_DEFLATE "permessage-deflate; client_no_context_takeover; server_no_context_takeover"

/**
 * MySQL Client
 */
#define SW_MYSQL_DEFAULT_HOST "127.0.0.1"
#define SW_MYSQL_DEFAULT_PORT 3306
#define SW_MYSQL_DEFAULT_CHARSET 33  // 0x21, utf8_general_ci

/**
 * PGSQL Client
 */
#define SW_PGSQL_CONNECT_TIMEOUT 3.0

/**
 * Coroutine
 */
#define SW_DEFAULT_C_STACK_SIZE (2 * 1024 * 1024)
#define SW_CORO_SUPPORT_BAILOUT 1
#define SW_CORO_SWAP_BAILOUT 1
#define SW_CORO_BAILOUT_EXIT_CODE 1
//#define SW_CONTEXT_PROTECT_STACK_PAGE    1
//#define SW_CONTEXT_DETECT_STACK_USAGE    1

#ifdef SW_DEBUG
#ifndef SW_LOG_TRACE_OPEN
#define SW_LOG_TRACE_OPEN 1
#endif
#endif

#endif /* SWOOLE_CONFIG_H_ */
