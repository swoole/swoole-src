# OpenSSL 3.5 QUIC Stream Processing Status

## Latest Session Progress

### Completed Work

1. **Stream Type Detection** ✅
   - Implemented bit-level stream ID analysis
   - Bit 0: client(0) vs server(1) initiated
   - Bit 1: bidirectional(0) vs unidirectional(1)
   - Properly identifies HTTP/3 control streams

2. **Stream Filtering** ✅
   - Unidirectional streams logged but not creating Stream objects
   - Bidirectional streams (HTTP requests) create Stream objects
   - Control stream data read from OpenSSL

3. **Active Connection Tracking** ✅
   - Listener maintains list of active connections
   - Event loop processes all connections
   - Connections removed when closed

### Current Status

**What Works:**
- ✅ HTTP/3 connection establishment
- ✅ TLS handshake (7ms)
- ✅ ALPN negotiation (h3)
- ✅ Client sends HTTP/3 requests
- ✅ Server receives requests
- ✅ PHP callback triggered

**What Doesn't Work:**
- ❌ Duplicate stream creation warnings
- ❌ No response sent to client
- ❌ nghttp3 layer integration incomplete

### Test Results

```
Server Output:
HTTP/3 Server starting...
Listening on: https://0.0.0.0:443 (HTTP/3)

WARNING: Stream 3 already exists
WARNING: Stream 7 already exists
WARNING: Stream 11 already exists
ALPN: Successfully negotiated h3
WARNING: Stream 0 already exists
Received HTTP/3 request:
  Method: 
  URI: 
  Protocol: HTTP/3
  Stream ID: 0
WARNING: nghttp3_conn_submit_response failed: ERR_STREAM_NOT_FOUND
WARNING: nghttp3_conn_read_stream failed
```

```
Client Output (curl):
* Established connection to localhost (127.0.0.1 port 443)
* using HTTP/3
> GET / HTTP/3
> Host: localhost
* Request completely sent off
[Waits indefinitely for response]
```

### Root Cause Analysis

#### Issue 1: Duplicate Stream Creation

**Problem:** HTTP/3 layer creates streams during initialization:
- `src/protocol/http3.cc:564` - Creates control stream (ID 3)
- `src/protocol/http3.cc:589-590` - Creates QPACK streams (IDs 7, 11)
- `src/protocol/http3.cc:622` - Creates request streams (ID 0, 4, 8...)

**When:** During `Connection::init()` or first HTTP/3 setup

**Conflict:** When `Connection::process_events()` tries to create the same streams after reading from OpenSSL

**Solution Needed:**
- Coordinate stream creation between OpenSSL and HTTP/3 layers
- Only create streams once
- Check if stream exists before creating

#### Issue 2: Stream Data Flow

**Current Flow:**
1. OpenSSL receives QUIC packets on UDP socket
2. `SSL_accept_stream()` returns new stream SSL objects
3. `Connection::process_events()` reads data with `SSL_read_ex()`
4. Data passed to `on_stream_data` callback
5. HTTP/3 layer tries to process data with `nghttp3_conn_read_stream()`

**Problem:** nghttp3 doesn't know about the stream because it wasn't created through nghttp3 API

**Correct Flow Should Be:**
1. OpenSSL receives packets
2. `Connection::process_events()` detects new streams
3. **Don't** create Stream objects in process_events
4. Pass stream data to HTTP/3 layer
5. HTTP/3 layer calls `open_stream()` to create Stream object
6. nghttp3 processes the stream data

### Code Locations

**Stream Creation:**
- `src/protocol/quic_openssl.cc:557` - Connection::create_stream()
- `src/protocol/quic_openssl.cc:769` - In process_events()
- `src/protocol/http3.cc:564` - HTTP/3 control stream
- `src/protocol/http3.cc:589-590` - QPACK streams
- `src/protocol/http3.cc:622` - Request streams

**Stream Processing:**
- `src/protocol/quic_openssl.cc:723` - Connection::process_events()
- `src/protocol/http3.cc:???` - HTTP/3 request handler

### Next Steps

1. **Remove Stream Creation from process_events()**
   - Don't call `create_stream()` in `Connection::process_events()`
   - Only read data and trigger callbacks
   - Let HTTP/3 layer manage stream lifecycle

2. **Fix HTTP/3 Integration**
   - Ensure control streams are handled by nghttp3
   - Pass stream data correctly to nghttp3
   - Fix `nghttp3_conn_read_stream()` errors

3. **Implement Response Sending**
   - Debug `nghttp3_conn_submit_response()` failure
   - Ensure stream exists in nghttp3 before responding
   - Write response data back through OpenSSL

4. **Clean Up Warnings**
   - Fix duplicate stream creation
   - Better error handling
   - Clear logging of stream lifecycle

## Architecture Notes

### HTTP/3 Stream Types

**Client-initiated bidirectional (0, 4, 8...):**
- HTTP requests/responses
- Must create Stream objects
- Data flows both ways

**Client-initiated unidirectional (2, 6, 10...):**
- Control stream (2)
- QPACK encoder (6)
- QPACK decoder (10)
- Server reads, doesn't write

**Server-initiated unidirectional (3, 7, 11...):**
- Control stream (3)
- QPACK encoder (7)
- QPACK decoder (10)
- Server writes, doesn't read

### OpenSSL 3.5 QUIC API

**Key Functions:**
- `SSL_accept_stream(ssl, flags)` - Accept new incoming stream
- `SSL_get_stream_id(stream_ssl)` - Get stream ID
- `SSL_read_ex(stream_ssl, buf, len, &nread)` - Read stream data
- `SSL_write_ex(stream_ssl, data, len, &nwritten)` - Write stream data
- `SSL_get_stream_read_state(stream_ssl)` - Check if stream finished
- `SSL_stream_conclude(stream_ssl, flags)` - Send FIN on stream

## Commit History

- `e3719e4` - WIP: Implement stream processing
- `a1ed780` - feat: Add stream type detection and filtering

## Branch

`claude/http3-quic-architecture-01SPxR5aCu7f3bguojNs5StA`
