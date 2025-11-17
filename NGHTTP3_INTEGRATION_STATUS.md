# nghttp3 Integration Status - Session 2

## Current Problem

**Error**: `nghttp3_conn_read_stream()` fails with error code 31, followed by `nghttp3_conn_submit_response()` failing with ERR_STREAM_NOT_FOUND.

**Symptoms**:
```
WARNING: nghttp3_conn_read_stream failed for stream 0: (unknown) (error code: 31)
WARNING: nghttp3_conn_submit_response failed: ERR_STREAM_NOT_FOUND
```

**Client behavior**: Request times out after 15 seconds, receives "HTTP/3 stream 0 reset by server"

## Fixes Attempted This Session

### 1. Added nghttp3 Stream Registration
**File**: `src/protocol/http3.cc:676`
```cpp
nghttp3_conn_set_stream_user_data(conn, stream_id, stream);
```
**Result**: No change - error persists

### 2. Fixed SETTINGS Transmission
**File**: `src/protocol/http3.cc:602-614`
```cpp
bool Connection::send_settings() {
    ssize_t rv = write_streams();  // Actually send SETTINGS via QUIC
    ...
}
```
**Rationale**: nghttp3 prepares SETTINGS but doesn't automatically send them
**Result**: Control stream data is now sent, but error persists

### 3. Process All Stream Types
**File**: `src/protocol/quic_openssl.cc:760-783`
```cpp
// Changed from processing only bidirectional streams
// to processing ALL streams (bidi + unidirectional)
```
**Rationale**: Client sends control streams (2, 6, 10) and QPACK data that nghttp3 needs to process
**Result**: Both request and control streams are now forwarded to HTTP/3 layer, but error persists

### 4. Added Debugging Logging
**File**: `src/protocol/http3.cc:678-679, 687-692`
- Added trace logging to see stream parameters
- Enhanced error messages with error codes
**Result**: Confirmed error code is 31

## Root Cause Analysis

### nghttp3 Error Code 31

Checking nghttp3 error codes, 31 is not a standard nghttp3 error (they're negative). This might be:
1. A different error enum
2. A return value that's not an error code
3. An issue with error reporting

### Stream Processing Flow

**Current flow**:
1. Client connects, QUIC handshake completes
2. Server creates control streams (3, 7, 11) and binds to nghttp3
3. Server sends SETTINGS on control stream 3
4. Client sends control stream 2 with SETTINGS ← Need to verify this is processed
5. Client sends request on stream 0
6. Server reads stream 0 data
7. **FAILURE**: `nghttp3_conn_read_stream(conn, 0, data, len, fin)` returns error 31

### Hypothesis

The issue might be:
1. **Control stream data not processed**: Client's control streams (2, 6, 10) might not be reaching nghttp3 properly
2. **Stream creation timing**: nghttp3 expects streams to be created in a specific order or state
3. **Missing initialization**: Some nghttp3 internal state isn't set up correctly
4. **Data format issue**: The data we're passing might not be valid HTTP/3 frames

## What's Working

✅ QUIC connection establishment (OpenSSL 3.5)
✅ TLS handshake and ALPN negotiation (h3)
✅ Stream acceptance via `SSL_accept_stream()`
✅ Stream type detection (bidirectional vs unidirectional)
✅ Data reading from QUIC streams
✅ Control stream binding in nghttp3
✅ SETTINGS frame generation and transmission
✅ All stream data forwarding to HTTP/3 layer

## What's NOT Working

❌ nghttp3 processing of request stream data
❌ HTTP/3 header parsing
❌ Response generation
❌ End-to-end request/response flow

## Next Steps

### Priority 1: Verify Control Stream Processing

Check if client's control stream (2) and QPACK streams (6, 10) are being received and processed:
- Add logging to show when unidirectional stream data is passed to `read_stream()`
- Verify `nghttp3_conn_read_stream()` is called for streams 2, 6, 10
- Check if these calls succeed or also fail with error 31

### Priority 2: Investigate Error Code 31

Options:
- Check nghttp3 source code for what error 31 means
- Look for alternative error reporting mechanisms
- Check if 31 is bytes processed rather than an error

### Priority 3: Review nghttp3 Server Initialization

Compare with working nghttp3 examples:
- Verify callback setup is correct
- Check if additional initialization is needed
- Confirm stream binding sequence

### Priority 4: Analyze HTTP/3 Frame Data

- Dump the actual bytes being passed to `nghttp3_conn_read_stream()`
- Verify they are valid HTTP/3 HEADERS frames
- Check frame format against HTTP/3 RFC

## Files Modified This Session

1. `src/protocol/http3.cc`:
   - `Connection::read_stream()`: Added stream registration, logging
   - `Connection::send_settings()`: Fixed to call `write_streams()`

2. `src/protocol/quic_openssl.cc`:
   - `Connection::process_events()`: Changed to process all stream types

## Testing Command

```bash
# Server
cd /home/user/swoole-src/examples
LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib php http3_server.php

# Client
LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib \
/usr/local/curl-http3/bin/curl --http3-only -k -v https://localhost:443/
```

## Progress Tracking

**Overall: ~75%**
- ✅ OpenSSL 3.5 QUIC integration (100%)
- ✅ Stream type detection and filtering (100%)
- ✅ Control stream binding (100%)
- ✅ SETTINGS transmission (100%)
- ⚠️ nghttp3 integration (70% - stream registration done, data processing failing)
- ❌ Request/response flow (0%)

## Key Insights

1. **Layer separation is critical**: QUIC layer handles transport, HTTP/3 layer handles HTTP semantics
2. **Control streams must be processed**: Both server and client control streams need bidirectional exchange
3. **nghttp3 expects specific initialization order**: Stream binding must happen before data processing
4. **Error codes need careful interpretation**: nghttp3 errors might not be where we expect them

---

**Session Date**: 2025-11-17
**Branch**: `claude/http3-quic-architecture-01SPxR5aCu7f3bguojNs5StA`
