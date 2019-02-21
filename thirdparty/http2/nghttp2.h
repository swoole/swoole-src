/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGHTTP2_H
#define NGHTTP2_H

/* Define WIN32 when build target is Win32 API (borrowed from
   libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#define WIN32
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#if defined(_MSC_VER) && (_MSC_VER < 1800)
/* MSVC < 2013 does not have inttypes.h because it is not C99
   compliant.  See compiler macros and version number in
   https://sourceforge.net/p/predef/wiki/Compilers/ */
#include <stdint.h>
#else /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <inttypes.h>
#endif /* !defined(_MSC_VER) || (_MSC_VER >= 1800) */
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>

static inline uint8_t *nghttp2_cpymem(uint8_t *dest, const void *src, size_t len) {
  if (len == 0) {
    return dest;
  }

  memcpy(dest, src, len);

  return dest + len;
}

#define nghttp2_min(A, B) ((A) < (B) ? (A) : (B))
#define nghttp2_max(A, B) ((A) > (B) ? (A) : (B))

#define DEBUGF(s, ...)

const char *nghttp2_strerror(int error_code);

#ifdef NGHTTP2_STATICLIB
#define NGHTTP2_EXTERN
#elif defined(WIN32)
#ifdef BUILDING_NGHTTP2
#define NGHTTP2_EXTERN __declspec(dllexport)
#else /* !BUILDING_NGHTTP2 */
#define NGHTTP2_EXTERN __declspec(dllimport)
#endif /* !BUILDING_NGHTTP2 */
#else  /* !defined(WIN32) */
#ifdef BUILDING_NGHTTP2
#define NGHTTP2_EXTERN __attribute__((visibility("default")))
#else /* !BUILDING_NGHTTP2 */
#define NGHTTP2_EXTERN
#endif /* !BUILDING_NGHTTP2 */
#endif /* !defined(WIN32) */

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over TLS.
 */
#define NGHTTP2_PROTO_VERSION_ID "h2"
/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_VERSION_ID`.
 */
#define NGHTTP2_PROTO_VERSION_ID_LEN 2

/**
 * @macro
 *
 * The serialized form of ALPN protocol identifier this library
 * supports.  Notice that first byte is the length of following
 * protocol identifier.  This is the same wire format of `TLS ALPN
 * extension <https://tools.ietf.org/html/rfc7301>`_.  This is useful
 * to process incoming ALPN tokens in wire format.
 */
#define NGHTTP2_PROTO_ALPN "\x2h2"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_PROTO_ALPN`.
 */
#define NGHTTP2_PROTO_ALPN_LEN (sizeof(NGHTTP2_PROTO_ALPN) - 1)

/**
 * @macro
 *
 * The protocol version identification string of this library
 * supports.  This identifier is used if HTTP/2 is used over cleartext
 * TCP.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "h2c"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLEARTEXT_PROTO_VERSION_ID`.
 */
#define NGHTTP2_CLEARTEXT_PROTO_VERSION_ID_LEN 3


/**
 * @macro
 *
 * The age of :type:`nghttp2_info`
 */
#define NGHTTP2_VERSION_AGE 1

/**
 * @struct
 *
 * This struct is what `nghttp2_version()` returns.  It holds
 * information about the particular nghttp2 version.
 */
typedef struct {
  /**
   * Age of this struct.  This instance of nghttp2 sets it to
   * :macro:`NGHTTP2_VERSION_AGE` but a future version may bump it and
   * add more struct fields at the bottom
   */
  int age;
  /**
   * the :macro:`NGHTTP2_VERSION_NUM` number (since age ==1)
   */
  int version_num;
  /**
   * points to the :macro:`NGHTTP2_VERSION` string (since age ==1)
   */
  const char *version_str;
  /**
   * points to the :macro:`NGHTTP2_PROTO_VERSION_ID` string this
   * instance implements (since age ==1)
   */
  const char *proto_str;
  /* -------- the above fields all exist when age == 1 */
} nghttp2_info;

/**
 * @macro
 *
 * The default weight of stream dependency.
 */
#define NGHTTP2_DEFAULT_WEIGHT 16

/**
 * @macro
 *
 * The maximum weight of stream dependency.
 */
#define NGHTTP2_MAX_WEIGHT 256

/**
 * @macro
 *
 * The minimum weight of stream dependency.
 */
#define NGHTTP2_MIN_WEIGHT 1

/**
 * @macro
 *
 * The maximum window size
 */
#define NGHTTP2_MAX_WINDOW_SIZE ((int32_t)((1U << 31) - 1))

/**
 * @macro
 *
 * The initial window size for stream level flow control.
 */
#define NGHTTP2_INITIAL_WINDOW_SIZE ((1 << 16) - 1)
/**
 * @macro
 *
 * The initial window size for connection level flow control.
 */
#define NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE ((1 << 16) - 1)

/**
 * @macro
 *
 * The default header table size.
 */
#define NGHTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)

/**
 * @macro
 *
 * The client magic string, which is the first 24 bytes byte string of
 * client connection preface.
 */
#define NGHTTP2_CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_MAGIC`.
 */
#define NGHTTP2_CLIENT_MAGIC_LEN 24

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * Out of buffer space.
   */
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback`,
   * :type:`nghttp2_recv_callback` and
   * :type:`nghttp2_send_data_callback` to indicate that the operation
   * would block.
   */
  NGHTTP2_ERR_WOULDBLOCK = -504,
  /**
   * General protocol error
   */
  NGHTTP2_ERR_PROTO = -505,
  /**
   * The frame is invalid.
   */
  NGHTTP2_ERR_INVALID_FRAME = -506,
  /**
   * The peer performed a shutdown on the connection.
   */
  NGHTTP2_ERR_EOF = -507,
  /**
   * Used as a return value from
   * :func:`nghttp2_data_source_read_callback` to indicate that data
   * transfer is postponed.  See
   * :func:`nghttp2_data_source_read_callback` for details.
   */
  NGHTTP2_ERR_DEFERRED = -508,
  /**
   * Stream ID has reached the maximum value.  Therefore no stream ID
   * is available.
   */
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
  /**
   * The stream is already closed; or the stream ID is invalid.
   */
  NGHTTP2_ERR_STREAM_CLOSED = -510,
  /**
   * RST_STREAM has been added to the outbound queue.  The stream is
   * in closing state.
   */
  NGHTTP2_ERR_STREAM_CLOSING = -511,
  /**
   * The transmission is not allowed for this stream (e.g., a frame
   * with END_STREAM flag set has already sent).
   */
  NGHTTP2_ERR_STREAM_SHUT_WR = -512,
  /**
   * The stream ID is invalid.
   */
  NGHTTP2_ERR_INVALID_STREAM_ID = -513,
  /**
   * The state of the stream is not valid (e.g., DATA cannot be sent
   * to the stream if response HEADERS has not been sent).
   */
  NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
  /**
   * Another DATA frame has already been deferred.
   */
  NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
  /**
   * Starting new stream is not allowed (e.g., GOAWAY has been sent
   * and/or received).
   */
  NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
  /**
   * GOAWAY has already been sent.
   */
  NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
  /**
   * The received frame contains the invalid header block (e.g., There
   * are duplicate header names; or the header names are not encoded
   * in US-ASCII character set and not lower cased; or the header name
   * is zero-length string; or the header value contains multiple
   * in-sequence NUL bytes).
   */
  NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
  /**
   * Indicates that the context is not suitable to perform the
   * requested operation.
   */
  NGHTTP2_ERR_INVALID_STATE = -519,
  /**
   * The user callback function failed due to the temporal error.
   */
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
  /**
   * The length of the frame is invalid, either too large or too small.
   */
  NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
  /**
   * Flow control error
   */
  NGHTTP2_ERR_FLOW_CONTROL = -524,
  /**
   * Insufficient buffer size given to function.
   */
  NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
  /**
   * Callback was paused by the application
   */
  NGHTTP2_ERR_PAUSE = -526,
  /**
   * There are too many in-flight SETTING frame and no more
   * transmission of SETTINGS is allowed.
   */
  NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
  /**
   * The server push is disabled.
   */
  NGHTTP2_ERR_PUSH_DISABLED = -528,
  /**
   * DATA or HEADERS frame for a given stream has been already
   * submitted and has not been fully processed yet.  Application
   * should wait for the transmission of the previously submitted
   * frame before submitting another.
   */
  NGHTTP2_ERR_DATA_EXIST = -529,
  /**
   * The current session is closing due to a connection error or
   * `nghttp2_session_terminate_session()` is called.
   */
  NGHTTP2_ERR_SESSION_CLOSING = -530,
  /**
   * Invalid HTTP header field was received and stream is going to be
   * closed.
   */
  NGHTTP2_ERR_HTTP_HEADER = -531,
  /**
   * Violation in HTTP messaging rule.
   */
  NGHTTP2_ERR_HTTP_MESSAGING = -532,
  /**
   * Stream was refused.
   */
  NGHTTP2_ERR_REFUSED_STREAM = -533,
  /**
   * Unexpected internal error, but recovered.
   */
  NGHTTP2_ERR_INTERNAL = -534,
  /**
   * Indicates that a processing was canceled.
   */
  NGHTTP2_ERR_CANCEL = -535,
  /**
   * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
   * under unexpected condition and processing was terminated (e.g.,
   * out of memory).  If application receives this error code, it must
   * stop using that :type:`nghttp2_session` object and only allowed
   * operation for that object is deallocate it using
   * `nghttp2_session_del()`.
   */
  NGHTTP2_ERR_FATAL = -900,
  /**
   * Out of memory.  This is a fatal error.
   */
  NGHTTP2_ERR_NOMEM = -901,
  /**
   * The user callback function failed.  This is a fatal error.
   */
  NGHTTP2_ERR_CALLBACK_FAILURE = -902,
  /**
   * Invalid client magic (see :macro:`NGHTTP2_CLIENT_MAGIC`) was
   * received and further processing is not possible.
   */
  NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903,
  /**
   * Possible flooding by peer was detected in this HTTP/2 session.
   * Flooding is measured by how many PING and SETTINGS frames with
   * ACK flag set are queued for transmission.  These frames are
   * response for the peer initiated frames, and peer can cause memory
   * exhaustion on server side to send these frames forever and does
   * not read network.
   */
  NGHTTP2_ERR_FLOODED = -904
} nghttp2_error;

/**
 * @struct
 *
 * The object representing single contiguous buffer.
 */
typedef struct {
  /**
   * The pointer to the buffer.
   */
  uint8_t *base;
  /**
   * The length of the buffer.
   */
  size_t len;
} nghttp2_vec;

struct nghttp2_rcbuf;

/**
 * @struct
 *
 * The object representing reference counted buffer.  The details of
 * this structure are intentionally hidden from the public API.
 */
typedef struct nghttp2_rcbuf nghttp2_rcbuf;

/**
 * @function
 *
 * Increments the reference count of |rcbuf| by 1.
 */
NGHTTP2_EXTERN void nghttp2_rcbuf_incref(nghttp2_rcbuf *rcbuf);

/**
 * @function
 *
 * Decrements the reference count of |rcbuf| by 1.  If the reference
 * count becomes zero, the object pointed by |rcbuf| will be freed.
 * In this case, application must not use |rcbuf| again.
 */
NGHTTP2_EXTERN void nghttp2_rcbuf_decref(nghttp2_rcbuf *rcbuf);

/**
 * @function
 *
 * Returns the underlying buffer managed by |rcbuf|.
 */
NGHTTP2_EXTERN nghttp2_vec nghttp2_rcbuf_get_buf(nghttp2_rcbuf *rcbuf);

/**
 * @enum
 *
 * The flags for header field name/value pair.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_NV_FLAG_NONE = 0,
  /**
   * Indicates that this name/value pair must not be indexed ("Literal
   * Header Field never Indexed" representation must be used in HPACK
   * encoding).  Other implementation calls this bit as "sensitive".
   */
  NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field name.  This could
   * improve performance.
   */
  NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02,
  /**
   * This flag is set solely by application.  If this flag is set, the
   * library does not make a copy of header field value.  This could
   * improve performance.
   */
  NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04
} nghttp2_nv_flag;

/**
 * @struct
 *
 * The name/value pair, which mainly used to represent header fields.
 */
typedef struct {
  /**
   * The |name| byte string.  If this struct is presented from library
   * (e.g., :type:`nghttp2_on_frame_recv_callback`), |name| is
   * guaranteed to be NULL-terminated.  For some callbacks
   * (:type:`nghttp2_before_frame_send_callback`,
   * :type:`nghttp2_on_frame_send_callback`, and
   * :type:`nghttp2_on_frame_not_send_callback`), it may not be
   * NULL-terminated if header field is passed from application with
   * the flag :enum:`NGHTTP2_NV_FLAG_NO_COPY_NAME`).  When application
   * is constructing this struct, |name| is not required to be
   * NULL-terminated.
   */
  uint8_t *name;
  /**
   * The |value| byte string.  If this struct is presented from
   * library (e.g., :type:`nghttp2_on_frame_recv_callback`), |value|
   * is guaranteed to be NULL-terminated.  For some callbacks
   * (:type:`nghttp2_before_frame_send_callback`,
   * :type:`nghttp2_on_frame_send_callback`, and
   * :type:`nghttp2_on_frame_not_send_callback`), it may not be
   * NULL-terminated if header field is passed from application with
   * the flag :enum:`NGHTTP2_NV_FLAG_NO_COPY_VALUE`).  When
   * application is constructing this struct, |value| is not required
   * to be NULL-terminated.
   */
  uint8_t *value;
  /**
   * The length of the |name|, excluding terminating NULL.
   */
  size_t namelen;
  /**
   * The length of the |value|, excluding terminating NULL.
   */
  size_t valuelen;
  /**
   * Bitwise OR of one or more of :type:`nghttp2_nv_flag`.
   */
  uint8_t flags;
} nghttp2_nv;

/**
 * @enum
 *
 * The frame types in HTTP/2 specification.
 */
typedef enum {
  /**
   * The DATA frame.
   */
  NGHTTP2_DATA = 0,
  /**
   * The HEADERS frame.
   */
  NGHTTP2_HEADERS = 0x01,
  /**
   * The PRIORITY frame.
   */
  NGHTTP2_PRIORITY = 0x02,
  /**
   * The RST_STREAM frame.
   */
  NGHTTP2_RST_STREAM = 0x03,
  /**
   * The SETTINGS frame.
   */
  NGHTTP2_SETTINGS = 0x04,
  /**
   * The PUSH_PROMISE frame.
   */
  NGHTTP2_PUSH_PROMISE = 0x05,
  /**
   * The PING frame.
   */
  NGHTTP2_PING = 0x06,
  /**
   * The GOAWAY frame.
   */
  NGHTTP2_GOAWAY = 0x07,
  /**
   * The WINDOW_UPDATE frame.
   */
  NGHTTP2_WINDOW_UPDATE = 0x08,
  /**
   * The CONTINUATION frame.  This frame type won't be passed to any
   * callbacks because the library processes this frame type and its
   * preceding HEADERS/PUSH_PROMISE as a single frame.
   */
  NGHTTP2_CONTINUATION = 0x09,
  /**
   * The ALTSVC frame, which is defined in `RFC 7383
   * <https://tools.ietf.org/html/rfc7838#section-4>`_.
   */
  NGHTTP2_ALTSVC = 0x0a
} nghttp2_frame_type;

/**
 * @enum
 *
 * The flags for HTTP/2 frames.  This enum defines all flags for all
 * frames.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_FLAG_NONE = 0,
  /**
   * The END_STREAM flag.
   */
  NGHTTP2_FLAG_END_STREAM = 0x01,
  /**
   * The END_HEADERS flag.
   */
  NGHTTP2_FLAG_END_HEADERS = 0x04,
  /**
   * The ACK flag.
   */
  NGHTTP2_FLAG_ACK = 0x01,
  /**
   * The PADDED flag.
   */
  NGHTTP2_FLAG_PADDED = 0x08,
  /**
   * The PRIORITY flag.
   */
  NGHTTP2_FLAG_PRIORITY = 0x20
} nghttp2_flag;

/**
 * @enum
 * The SETTINGS ID.
 */
typedef enum {
  /**
   * SETTINGS_HEADER_TABLE_SIZE
   */
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
  /**
   * SETTINGS_ENABLE_PUSH
   */
  NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
  /**
   * SETTINGS_MAX_CONCURRENT_STREAMS
   */
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
  /**
   * SETTINGS_INITIAL_WINDOW_SIZE
   */
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
  /**
   * SETTINGS_MAX_FRAME_SIZE
   */
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
  /**
   * SETTINGS_MAX_HEADER_LIST_SIZE
   */
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06
} nghttp2_settings_id;
/* Note: If we add SETTINGS, update the capacity of
   NGHTTP2_INBOUND_NUM_IV as well */

/**
 * @macro
 *
 * .. warning::
 *
 *   Deprecated.  The initial max concurrent streams is 0xffffffffu.
 *
 * Default maximum number of incoming concurrent streams.  Use
 * `nghttp2_submit_settings()` with
 * :enum:`NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS` to change the
 * maximum number of incoming concurrent streams.
 *
 * .. note::
 *
 *   The maximum number of outgoing concurrent streams is 100 by
 *   default.
 */
#define NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/**
 * @enum
 * The status codes for the RST_STREAM and GOAWAY frames.
 */
typedef enum {
  /**
   * No errors.
   */
  NGHTTP2_NO_ERROR = 0x00,
  /**
   * PROTOCOL_ERROR
   */
  NGHTTP2_PROTOCOL_ERROR = 0x01,
  /**
   * INTERNAL_ERROR
   */
  NGHTTP2_INTERNAL_ERROR = 0x02,
  /**
   * FLOW_CONTROL_ERROR
   */
  NGHTTP2_FLOW_CONTROL_ERROR = 0x03,
  /**
   * SETTINGS_TIMEOUT
   */
  NGHTTP2_SETTINGS_TIMEOUT = 0x04,
  /**
   * STREAM_CLOSED
   */
  NGHTTP2_STREAM_CLOSED = 0x05,
  /**
   * FRAME_SIZE_ERROR
   */
  NGHTTP2_FRAME_SIZE_ERROR = 0x06,
  /**
   * REFUSED_STREAM
   */
  NGHTTP2_REFUSED_STREAM = 0x07,
  /**
   * CANCEL
   */
  NGHTTP2_CANCEL = 0x08,
  /**
   * COMPRESSION_ERROR
   */
  NGHTTP2_COMPRESSION_ERROR = 0x09,
  /**
   * CONNECT_ERROR
   */
  NGHTTP2_CONNECT_ERROR = 0x0a,
  /**
   * ENHANCE_YOUR_CALM
   */
  NGHTTP2_ENHANCE_YOUR_CALM = 0x0b,
  /**
   * INADEQUATE_SECURITY
   */
  NGHTTP2_INADEQUATE_SECURITY = 0x0c,
  /**
   * HTTP_1_1_REQUIRED
   */
  NGHTTP2_HTTP_1_1_REQUIRED = 0x0d
} nghttp2_error_code;

/**
 * @struct
 * The frame header.
 */
typedef struct {
  /**
   * The length field of this frame, excluding frame header.
   */
  size_t length;
  /**
   * The stream identifier (aka, stream ID)
   */
  int32_t stream_id;
  /**
   * The type of this frame.  See `nghttp2_frame_type`.
   */
  uint8_t type;
  /**
   * The flags.
   */
  uint8_t flags;
  /**
   * Reserved bit in frame header.  Currently, this is always set to 0
   * and application should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_frame_hd;

/**
 * @union
 *
 * This union represents the some kind of data source passed to
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef union {
  /**
   * The integer field, suitable for a file descriptor.
   */
  int fd;
  /**
   * The pointer to an arbitrary object.
   */
  void *ptr;
} nghttp2_data_source;

/**
 * @enum
 *
 * The flags used to set in |data_flags| output parameter in
 * :type:`nghttp2_data_source_read_callback`.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_DATA_FLAG_NONE = 0,
  /**
   * Indicates EOF was sensed.
   */
  NGHTTP2_DATA_FLAG_EOF = 0x01,
  /**
   * Indicates that END_STREAM flag must not be set even if
   * NGHTTP2_DATA_FLAG_EOF is set.  Usually this flag is used to send
   * trailer fields with `nghttp2_submit_request()` or
   * `nghttp2_submit_response()`.
   */
  NGHTTP2_DATA_FLAG_NO_END_STREAM = 0x02,
  /**
   * Indicates that application will send complete DATA frame in
   * :type:`nghttp2_send_data_callback`.
   */
  NGHTTP2_DATA_FLAG_NO_COPY = 0x04
} nghttp2_data_flag;


/**
 * @functypedef
 *
 * Custom memory allocator to replace malloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_malloc)(size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace free().  The |mem_user_data| is
 * the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void (*nghttp2_free)(void *ptr, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace calloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *mem_user_data);

/**
 * @functypedef
 *
 * Custom memory allocator to replace realloc().  The |mem_user_data|
 * is the mem_user_data member of :type:`nghttp2_mem` structure.
 */
typedef void *(*nghttp2_realloc)(void *ptr, size_t size, void *mem_user_data);

typedef struct {
  /**
   * An arbitrary user supplied data.  This is passed to each
   * allocator function.
   */
  void *mem_user_data;
  /**
   * Custom allocator function to replace malloc().
   */
  nghttp2_malloc malloc;
  /**
   * Custom allocator function to replace free().
   */
  nghttp2_free free;
  /**
   * Custom allocator function to replace calloc().
   */
  nghttp2_calloc calloc;
  /**
   * Custom allocator function to replace realloc().
   */
  nghttp2_realloc realloc;
} nghttp2_mem;


/**
 * @struct
 *
 * The DATA frame.  The received data is delivered via
 * :type:`nghttp2_on_data_chunk_recv_callback`.
 */
typedef struct {
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
} nghttp2_data;

/**
 * @enum
 *
 * The category of HEADERS, which indicates the role of the frame.  In
 * HTTP/2 spec, request, response, push response and other arbitrary
 * headers (e.g., trailer fields) are all called just HEADERS.  To
 * give the application the role of incoming HEADERS frame, we define
 * several categories.
 */
typedef enum {
  /**
   * The HEADERS frame is opening new stream, which is analogous to
   * SYN_STREAM in SPDY.
   */
  NGHTTP2_HCAT_REQUEST = 0,
  /**
   * The HEADERS frame is the first response headers, which is
   * analogous to SYN_REPLY in SPDY.
   */
  NGHTTP2_HCAT_RESPONSE = 1,
  /**
   * The HEADERS frame is the first headers sent against reserved
   * stream.
   */
  NGHTTP2_HCAT_PUSH_RESPONSE = 2,
  /**
   * The HEADERS frame which does not apply for the above categories,
   * which is analogous to HEADERS in SPDY.  If non-final response
   * (e.g., status 1xx) is used, final response HEADERS frame will be
   * categorized here.
   */
  NGHTTP2_HCAT_HEADERS = 3
} nghttp2_headers_category;

/**
 * @struct
 *
 * The structure to specify stream dependency.
 */
typedef struct {
  /**
   * The stream ID of the stream to depend on.  Specifying 0 makes
   * stream not depend any other stream.
   */
  int32_t stream_id;
  /**
   * The weight of this dependency.
   */
  int32_t weight;
  /**
   * nonzero means exclusive dependency
   */
  uint8_t exclusive;
} nghttp2_priority_spec;

/**
 * @struct
 *
 * The HEADERS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The priority specification
   */
  nghttp2_priority_spec pri_spec;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The category of this HEADERS frame.
   */
  nghttp2_headers_category cat;
} nghttp2_headers;

/**
 * @struct
 *
 * The PRIORITY frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The priority specification.
   */
  nghttp2_priority_spec pri_spec;
} nghttp2_priority;

/**
 * @struct
 *
 * The RST_STREAM frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The error code.  See :type:`nghttp2_error_code`.
   */
  uint32_t error_code;
} nghttp2_rst_stream;

/**
 * @struct
 *
 * The SETTINGS ID/Value pair.  It has the following members:
 */
typedef struct {
  /**
   * The SETTINGS ID.  See :type:`nghttp2_settings_id`.
   */
  int32_t settings_id;
  /**
   * The value of this entry.
   */
  uint32_t value;
} nghttp2_settings_entry;

/**
 * @struct
 *
 * The SETTINGS frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The number of SETTINGS ID/Value pairs in |iv|.
   */
  size_t niv;
  /**
   * The pointer to the array of SETTINGS ID/Value pair.
   */
  nghttp2_settings_entry *iv;
} nghttp2_settings;

/**
 * @struct
 *
 * The PUSH_PROMISE frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The length of the padding in this frame.  This includes PAD_HIGH
   * and PAD_LOW.
   */
  size_t padlen;
  /**
   * The name/value pairs.
   */
  nghttp2_nv *nva;
  /**
   * The number of name/value pairs in |nva|.
   */
  size_t nvlen;
  /**
   * The promised stream ID
   */
  int32_t promised_stream_id;
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_push_promise;

/**
 * @struct
 *
 * The PING frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The opaque data
   */
  uint8_t opaque_data[8];
} nghttp2_ping;

/**
 * @struct
 *
 * The GOAWAY frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The last stream stream ID.
   */
  int32_t last_stream_id;
  /**
   * The error code.  See :type:`nghttp2_error_code`.
   */
  uint32_t error_code;
  /**
   * The additional debug data
   */
  uint8_t *opaque_data;
  /**
   * The length of |opaque_data| member.
   */
  size_t opaque_data_len;
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_goaway;

/**
 * @struct
 *
 * The WINDOW_UPDATE frame.  It has the following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The window size increment.
   */
  int32_t window_size_increment;
  /**
   * Reserved bit.  Currently this is always set to 0 and application
   * should not expect something useful in here.
   */
  uint8_t reserved;
} nghttp2_window_update;

/**
 * @struct
 *
 * The extension frame.  It has following members:
 */
typedef struct {
  /**
   * The frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The pointer to extension payload.  The exact pointer type is
   * determined by hd.type.
   *
   * Currently, no extension is supported.  This is a place holder for
   * the future extensions.
   */
  void *payload;
} nghttp2_extension;

/**
 * @union
 *
 * This union includes all frames to pass them to various function
 * calls as nghttp2_frame type.  The CONTINUATION frame is omitted
 * from here because the library deals with it internally.
 */
typedef union {
  /**
   * The frame header, which is convenient to inspect frame header.
   */
  nghttp2_frame_hd hd;
  /**
   * The DATA frame.
   */
  nghttp2_data data;
  /**
   * The HEADERS frame.
   */
  nghttp2_headers headers;
  /**
   * The PRIORITY frame.
   */
  nghttp2_priority priority;
  /**
   * The RST_STREAM frame.
   */
  nghttp2_rst_stream rst_stream;
  /**
   * The SETTINGS frame.
   */
  nghttp2_settings settings;
  /**
   * The PUSH_PROMISE frame.
   */
  nghttp2_push_promise push_promise;
  /**
   * The PING frame.
   */
  nghttp2_ping ping;
  /**
   * The GOAWAY frame.
   */
  nghttp2_goaway goaway;
  /**
   * The WINDOW_UPDATE frame.
   */
  nghttp2_window_update window_update;
  /**
   * The extension frame.
   */
  nghttp2_extension ext;
} nghttp2_frame;

/* HPACK API */

struct nghttp2_hd_deflater;

/**
 * @struct
 *
 * HPACK deflater object.
 */
typedef struct nghttp2_hd_deflater nghttp2_hd_deflater;

/**
 * @function
 *
 * Initializes |*deflater_ptr| for deflating name/values pairs.
 *
 * The |max_deflate_dynamic_table_size| is the upper bound of header
 * table size the deflater will use.
 *
 * If this function fails, |*deflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                       size_t max_deflate_dynamic_table_size);

/**
 * @function
 *
 * Like `nghttp2_hd_deflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_hd_deflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
NGHTTP2_EXTERN int
nghttp2_hd_deflate_new2(nghttp2_hd_deflater **deflater_ptr,
                        size_t max_deflate_dynamic_table_size,
                        nghttp2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |deflater|.
 */
NGHTTP2_EXTERN void nghttp2_hd_deflate_del(nghttp2_hd_deflater *deflater);

/**
 * @function
 *
 * Changes header table size of the |deflater| to
 * |settings_max_dynamic_table_size| bytes.  This may trigger eviction
 * in the dynamic table.
 *
 * The |settings_max_dynamic_table_size| should be the value received
 * in SETTINGS_HEADER_TABLE_SIZE.
 *
 * The deflater never uses more memory than
 * ``max_deflate_dynamic_table_size`` bytes specified in
 * `nghttp2_hd_deflate_new()`.  Therefore, if
 * |settings_max_dynamic_table_size| >
 * ``max_deflate_dynamic_table_size``, resulting maximum table size
 * becomes ``max_deflate_dynamic_table_size``.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int
nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater,
                                     size_t settings_max_dynamic_table_size);

/**
 * @function
 *
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |buf| of length |buflen|.
 *
 * If |buf| is not large enough to store the deflated header block,
 * this function fails with :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`.  The
 * caller should use `nghttp2_hd_deflate_bound()` to know the upper
 * bound of buffer size required to deflate given header name/value
 * pairs.
 *
 * Once this function fails, subsequent call of this function always
 * returns :enum:`NGHTTP2_ERR_HEADER_COMP`.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Deflation process has failed.
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
NGHTTP2_EXTERN ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                                             uint8_t *buf, size_t buflen,
                                             const nghttp2_nv *nva,
                                             size_t nvlen);

/**
 * @function
 *
 * Deflates the |nva|, which has the |nvlen| name/value pairs, into
 * the |veclen| size of buf vector |vec|.  The each size of buffer
 * must be set in len field of :type:`nghttp2_vec`.  If and only if
 * one chunk is filled up completely, next chunk will be used.  If
 * |vec| is not large enough to store the deflated header block, this
 * function fails with :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`.  The caller
 * should use `nghttp2_hd_deflate_bound()` to know the upper bound of
 * buffer size required to deflate given header name/value pairs.
 *
 * Once this function fails, subsequent call of this function always
 * returns :enum:`NGHTTP2_ERR_HEADER_COMP`.
 *
 * After this function returns, it is safe to delete the |nva|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Deflation process has failed.
 * :enum:`NGHTTP2_ERR_INSUFF_BUFSIZE`
 *     The provided |buflen| size is too small to hold the output.
 */
NGHTTP2_EXTERN ssize_t nghttp2_hd_deflate_hd_vec(nghttp2_hd_deflater *deflater,
                                                 const nghttp2_vec *vec,
                                                 size_t veclen,
                                                 const nghttp2_nv *nva,
                                                 size_t nvlen);

/**
 * @function
 *
 * Returns an upper bound on the compressed size after deflation of
 * |nva| of length |nvlen|.
 */
NGHTTP2_EXTERN size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                               const nghttp2_nv *nva,
                                               size_t nvlen);

/**
 * @function
 *
 * Returns the number of entries that header table of |deflater|
 * contains.  This is the sum of the number of static table and
 * dynamic table, so the return value is at least 61.
 */
NGHTTP2_EXTERN
size_t nghttp2_hd_deflate_get_num_table_entries(nghttp2_hd_deflater *deflater);

/**
 * @function
 *
 * Returns the table entry denoted by |idx| from header table of
 * |deflater|.  The |idx| is 1-based, and idx=1 returns first entry of
 * static table.  idx=62 returns first entry of dynamic table if it
 * exists.  Specifying idx=0 is error, and this function returns NULL.
 * If |idx| is strictly greater than the number of entries the tables
 * contain, this function returns NULL.
 */
NGHTTP2_EXTERN
const nghttp2_nv *
nghttp2_hd_deflate_get_table_entry(nghttp2_hd_deflater *deflater, size_t idx);

/**
 * @function
 *
 * Returns the used dynamic table size, including the overhead 32
 * bytes per entry described in RFC 7541.
 */
NGHTTP2_EXTERN
size_t nghttp2_hd_deflate_get_dynamic_table_size(nghttp2_hd_deflater *deflater);

/**
 * @function
 *
 * Returns the maximum dynamic table size.
 */
NGHTTP2_EXTERN
size_t
nghttp2_hd_deflate_get_max_dynamic_table_size(nghttp2_hd_deflater *deflater);

struct nghttp2_hd_inflater;

/**
 * @struct
 *
 * HPACK inflater object.
 */
typedef struct nghttp2_hd_inflater nghttp2_hd_inflater;

/**
 * @function
 *
 * Initializes |*inflater_ptr| for inflating name/values pairs.
 *
 * If this function fails, |*inflater_ptr| is left untouched.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 */
NGHTTP2_EXTERN int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);

/**
 * @function
 *
 * Like `nghttp2_hd_inflate_new()`, but with additional custom memory
 * allocator specified in the |mem|.
 *
 * The |mem| can be ``NULL`` and the call is equivalent to
 * `nghttp2_hd_inflate_new()`.
 *
 * This function does not take ownership |mem|.  The application is
 * responsible for freeing |mem|.
 *
 * The library code does not refer to |mem| pointer after this
 * function returns, so the application can safely free it.
 */
NGHTTP2_EXTERN int nghttp2_hd_inflate_new2(nghttp2_hd_inflater **inflater_ptr,
                                           nghttp2_mem *mem);

/**
 * @function
 *
 * Deallocates any resources allocated for |inflater|.
 */
NGHTTP2_EXTERN void nghttp2_hd_inflate_del(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Changes header table size in the |inflater|.  This may trigger
 * eviction in the dynamic table.
 *
 * The |settings_max_dynamic_table_size| should be the value
 * transmitted in SETTINGS_HEADER_TABLE_SIZE.
 *
 * This function must not be called while header block is being
 * inflated.  In other words, this function must be called after
 * initialization of |inflater|, but before calling
 * `nghttp2_hd_inflate_hd2()`, or after
 * `nghttp2_hd_inflate_end_headers()`.  Otherwise,
 * `NGHTTP2_ERR_INVALID_STATE` was returned.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_INVALID_STATE`
 *     The function is called while header block is being inflated.
 *     Probably, application missed to call
 *     `nghttp2_hd_inflate_end_headers()`.
 */
NGHTTP2_EXTERN int
nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater,
                                     size_t settings_max_dynamic_table_size);

/**
 * @enum
 *
 * The flags for header inflation.
 */
typedef enum {
  /**
   * No flag set.
   */
  NGHTTP2_HD_INFLATE_NONE = 0,
  /**
   * Indicates all headers were inflated.
   */
  NGHTTP2_HD_INFLATE_FINAL = 0x01,
  /**
   * Indicates a header was emitted.
   */
  NGHTTP2_HD_INFLATE_EMIT = 0x02
} nghttp2_hd_inflate_flag;

/**
 * @function
 *
 * .. warning::
 *
 *   Deprecated.  Use `nghttp2_hd_inflate_hd2()` instead.
 *
 * Inflates name/value block stored in |in| with length |inlen|.  This
 * function performs decompression.  For each successful emission of
 * header name/value pair, :enum:`NGHTTP2_HD_INFLATE_EMIT` is set in
 * |*inflate_flags| and name/value pair is assigned to the |nv_out|
 * and the function returns.  The caller must not free the members of
 * |nv_out|.
 *
 * The |nv_out| may include pointers to the memory region in the |in|.
 * The caller must retain the |in| while the |nv_out| is used.
 *
 * The application should call this function repeatedly until the
 * ``(*inflate_flags) & NGHTTP2_HD_INFLATE_FINAL`` is nonzero and
 * return value is non-negative.  This means the all input values are
 * processed successfully.  Then the application must call
 * `nghttp2_hd_inflate_end_headers()` to prepare for the next header
 * block input.
 *
 * The caller can feed complete compressed header block.  It also can
 * feed it in several chunks.  The caller must set |in_final| to
 * nonzero if the given input is the last block of the compressed
 * header.
 *
 * This function returns the number of bytes processed if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Inflation process has failed.
 * :enum:`NGHTTP2_ERR_BUFFER_ERROR`
 *     The header field name or value is too large.
 *
 * Example follows::
 *
 *     int inflate_header_block(nghttp2_hd_inflater *hd_inflater,
 *                              uint8_t *in, size_t inlen, int final)
 *     {
 *         ssize_t rv;
 *
 *         for(;;) {
 *             nghttp2_nv nv;
 *             int inflate_flags = 0;
 *
 *             rv = nghttp2_hd_inflate_hd(hd_inflater, &nv, &inflate_flags,
 *                                        in, inlen, final);
 *
 *             if(rv < 0) {
 *                 fprintf(stderr, "inflate failed with error code %zd", rv);
 *                 return -1;
 *             }
 *
 *             in += rv;
 *             inlen -= rv;
 *
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
 *                 fwrite(nv.name, nv.namelen, 1, stderr);
 *                 fprintf(stderr, ": ");
 *                 fwrite(nv.value, nv.valuelen, 1, stderr);
 *                 fprintf(stderr, "\n");
 *             }
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
 *                 nghttp2_hd_inflate_end_headers(hd_inflater);
 *                 break;
 *             }
 *             if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
 *                inlen == 0) {
 *                break;
 *             }
 *         }
 *
 *         return 0;
 *     }
 *
 */
NGHTTP2_EXTERN ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater,
                                             nghttp2_nv *nv_out,
                                             int *inflate_flags, uint8_t *in,
                                             size_t inlen, int in_final);

/**
 * @function
 *
 * Inflates name/value block stored in |in| with length |inlen|.  This
 * function performs decompression.  For each successful emission of
 * header name/value pair, :enum:`NGHTTP2_HD_INFLATE_EMIT` is set in
 * |*inflate_flags| and name/value pair is assigned to the |nv_out|
 * and the function returns.  The caller must not free the members of
 * |nv_out|.
 *
 * The |nv_out| may include pointers to the memory region in the |in|.
 * The caller must retain the |in| while the |nv_out| is used.
 *
 * The application should call this function repeatedly until the
 * ``(*inflate_flags) & NGHTTP2_HD_INFLATE_FINAL`` is nonzero and
 * return value is non-negative.  If that happens, all given input
 * data (|inlen| bytes) are processed successfully.  Then the
 * application must call `nghttp2_hd_inflate_end_headers()` to prepare
 * for the next header block input.
 *
 * In other words, if |in_final| is nonzero, and this function returns
 * |inlen|, you can assert that :enum:`NGHTTP2_HD_INFLATE_FINAL` is
 * set in |*inflate_flags|.
 *
 * The caller can feed complete compressed header block.  It also can
 * feed it in several chunks.  The caller must set |in_final| to
 * nonzero if the given input is the last block of the compressed
 * header.
 *
 * This function returns the number of bytes processed if it succeeds,
 * or one of the following negative error codes:
 *
 * :enum:`NGHTTP2_ERR_NOMEM`
 *     Out of memory.
 * :enum:`NGHTTP2_ERR_HEADER_COMP`
 *     Inflation process has failed.
 * :enum:`NGHTTP2_ERR_BUFFER_ERROR`
 *     The header field name or value is too large.
 *
 * Example follows::
 *
 *     int inflate_header_block(nghttp2_hd_inflater *hd_inflater,
 *                              uint8_t *in, size_t inlen, int final)
 *     {
 *         ssize_t rv;
 *
 *         for(;;) {
 *             nghttp2_nv nv;
 *             int inflate_flags = 0;
 *
 *             rv = nghttp2_hd_inflate_hd2(hd_inflater, &nv, &inflate_flags,
 *                                         in, inlen, final);
 *
 *             if(rv < 0) {
 *                 fprintf(stderr, "inflate failed with error code %zd", rv);
 *                 return -1;
 *             }
 *
 *             in += rv;
 *             inlen -= rv;
 *
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
 *                 fwrite(nv.name, nv.namelen, 1, stderr);
 *                 fprintf(stderr, ": ");
 *                 fwrite(nv.value, nv.valuelen, 1, stderr);
 *                 fprintf(stderr, "\n");
 *             }
 *             if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
 *                 nghttp2_hd_inflate_end_headers(hd_inflater);
 *                 break;
 *             }
 *             if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
 *                inlen == 0) {
 *                break;
 *             }
 *         }
 *
 *         return 0;
 *     }
 *
 */
NGHTTP2_EXTERN ssize_t nghttp2_hd_inflate_hd2(nghttp2_hd_inflater *inflater,
                                              nghttp2_nv *nv_out,
                                              int *inflate_flags,
                                              const uint8_t *in, size_t inlen,
                                              int in_final);

/**
 * @function
 *
 * Signals the end of decompression for one header block.
 *
 * This function returns 0 if it succeeds. Currently this function
 * always succeeds.
 */
NGHTTP2_EXTERN int
nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Returns the number of entries that header table of |inflater|
 * contains.  This is the sum of the number of static table and
 * dynamic table, so the return value is at least 61.
 */
NGHTTP2_EXTERN
size_t nghttp2_hd_inflate_get_num_table_entries(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Returns the table entry denoted by |idx| from header table of
 * |inflater|.  The |idx| is 1-based, and idx=1 returns first entry of
 * static table.  idx=62 returns first entry of dynamic table if it
 * exists.  Specifying idx=0 is error, and this function returns NULL.
 * If |idx| is strictly greater than the number of entries the tables
 * contain, this function returns NULL.
 */
NGHTTP2_EXTERN
const nghttp2_nv *
nghttp2_hd_inflate_get_table_entry(nghttp2_hd_inflater *inflater, size_t idx);

/**
 * @function
 *
 * Returns the used dynamic table size, including the overhead 32
 * bytes per entry described in RFC 7541.
 */
NGHTTP2_EXTERN
size_t nghttp2_hd_inflate_get_dynamic_table_size(nghttp2_hd_inflater *inflater);

/**
 * @function
 *
 * Returns the maximum dynamic table size.
 */
NGHTTP2_EXTERN
size_t
nghttp2_hd_inflate_get_max_dynamic_table_size(nghttp2_hd_inflater *inflater);

/**
 * @enum
 *
 * State of stream as described in RFC 7540.
 */
typedef enum {
  /**
   * idle state.
   */
  NGHTTP2_STREAM_STATE_IDLE = 1,
  /**
   * open state.
   */
  NGHTTP2_STREAM_STATE_OPEN,
  /**
   * reserved (local) state.
   */
  NGHTTP2_STREAM_STATE_RESERVED_LOCAL,
  /**
   * reserved (remote) state.
   */
  NGHTTP2_STREAM_STATE_RESERVED_REMOTE,
  /**
   * half closed (local) state.
   */
  NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
  /**
   * half closed (remote) state.
   */
  NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE,
  /**
   * closed state.
   */
  NGHTTP2_STREAM_STATE_CLOSED
} nghttp2_stream_proto_state;

/**
 * @functypedef
 *
 * Callback function invoked when the library outputs debug logging.
 * The function is called with arguments suitable for ``vfprintf(3)``
 *
 * The debug output is only enabled if the library is built with
 * ``DEBUGBUILD`` macro defined.
 */
typedef void (*nghttp2_debug_vprintf_callback)(const char *format,
                                               va_list args);

/**
 * @function
 *
 * Sets a debug output callback called by the library when built with
 * ``DEBUGBUILD`` macro defined.  If this option is not used, debug
 * log is written into standard error output.
 *
 * For builds without ``DEBUGBUILD`` macro defined, this function is
 * noop.
 *
 * Note that building with ``DEBUGBUILD`` may cause significant
 * performance penalty to libnghttp2 because of extra processing.  It
 * should be used for debugging purpose only.
 *
 * .. Warning::
 *
 *   Building with ``DEBUGBUILD`` may cause significant performance
 *   penalty to libnghttp2 because of extra processing.  It should be
 *   used for debugging purpose only.  We write this two times because
 *   this is important.
 */
NGHTTP2_EXTERN void nghttp2_set_debug_vprintf_callback(
    nghttp2_debug_vprintf_callback debug_vprintf_callback);
    
#ifdef __cplusplus
}
#endif

#endif /* NGHTTP2_H */
