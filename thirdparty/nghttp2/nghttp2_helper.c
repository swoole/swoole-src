/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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

#include "nghttp2.h"
#include "nghttp2_mem.h"

#include <netinet/in.h>
#include <assert.h>
#include <string.h>


const char *nghttp2_strerror(int error_code) {
  switch (error_code) {
  case 0:
    return "Success";
  case NGHTTP2_ERR_INVALID_ARGUMENT:
    return "Invalid argument";
  case NGHTTP2_ERR_BUFFER_ERROR:
    return "Out of buffer space";
  case NGHTTP2_ERR_UNSUPPORTED_VERSION:
    return "Unsupported SPDY version";
  case NGHTTP2_ERR_WOULDBLOCK:
    return "Operation would block";
  case NGHTTP2_ERR_PROTO:
    return "Protocol error";
  case NGHTTP2_ERR_INVALID_FRAME:
    return "Invalid frame octets";
  case NGHTTP2_ERR_EOF:
    return "EOF";
  case NGHTTP2_ERR_DEFERRED:
    return "Data transfer deferred";
  case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
    return "No more Stream ID available";
  case NGHTTP2_ERR_STREAM_CLOSED:
    return "Stream was already closed or invalid";
  case NGHTTP2_ERR_STREAM_CLOSING:
    return "Stream is closing";
  case NGHTTP2_ERR_STREAM_SHUT_WR:
    return "The transmission is not allowed for this stream";
  case NGHTTP2_ERR_INVALID_STREAM_ID:
    return "Stream ID is invalid";
  case NGHTTP2_ERR_INVALID_STREAM_STATE:
    return "Invalid stream state";
  case NGHTTP2_ERR_DEFERRED_DATA_EXIST:
    return "Another DATA frame has already been deferred";
  case NGHTTP2_ERR_START_STREAM_NOT_ALLOWED:
    return "request HEADERS is not allowed";
  case NGHTTP2_ERR_GOAWAY_ALREADY_SENT:
    return "GOAWAY has already been sent";
  case NGHTTP2_ERR_INVALID_HEADER_BLOCK:
    return "Invalid header block";
  case NGHTTP2_ERR_INVALID_STATE:
    return "Invalid state";
  case NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
    return "The user callback function failed due to the temporal error";
  case NGHTTP2_ERR_FRAME_SIZE_ERROR:
    return "The length of the frame is invalid";
  case NGHTTP2_ERR_HEADER_COMP:
    return "Header compression/decompression error";
  case NGHTTP2_ERR_FLOW_CONTROL:
    return "Flow control error";
  case NGHTTP2_ERR_INSUFF_BUFSIZE:
    return "Insufficient buffer size given to function";
  case NGHTTP2_ERR_PAUSE:
    return "Callback was paused by the application";
  case NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS:
    return "Too many inflight SETTINGS";
  case NGHTTP2_ERR_PUSH_DISABLED:
    return "Server push is disabled by peer";
  case NGHTTP2_ERR_DATA_EXIST:
    return "DATA or HEADERS frame has already been submitted for the stream";
  case NGHTTP2_ERR_SESSION_CLOSING:
    return "The current session is closing";
  case NGHTTP2_ERR_HTTP_HEADER:
    return "Invalid HTTP header field was received";
  case NGHTTP2_ERR_HTTP_MESSAGING:
    return "Violation in HTTP messaging rule";
  case NGHTTP2_ERR_REFUSED_STREAM:
    return "Stream was refused";
  case NGHTTP2_ERR_INTERNAL:
    return "Internal error";
  case NGHTTP2_ERR_CANCEL:
    return "Cancel";
  case NGHTTP2_ERR_NOMEM:
    return "Out of memory";
  case NGHTTP2_ERR_CALLBACK_FAILURE:
    return "The user callback function failed";
  case NGHTTP2_ERR_BAD_CLIENT_MAGIC:
    return "Received bad client magic byte string";
  case NGHTTP2_ERR_FLOODED:
    return "Flooding was detected in this HTTP/2 session, and it must be "
           "closed";
  default:
    return "Unknown error code";
  }
}
