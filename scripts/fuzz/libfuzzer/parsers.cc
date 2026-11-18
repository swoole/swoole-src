// libFuzzer harness for the pure protocol parsers. The first input byte selects the target, the rest is the payload.
// Inputs are always copied into exact-size heap buffers so that ASAN reports any read past the end.
// Build and run: scripts/fuzz/libfuzzer/build.sh && /tmp/lf_build/parsers_fuzz corpus_dir

#include "swoole_api.h"
#include "swoole_string.h"
#include "swoole_protocol.h"
#include "swoole_websocket.h"
#include "swoole_http.h"
#include "swoole_http2.h"
#include "swoole_mqtt.h"
#include "swoole_redis.h"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

using namespace swoole;

namespace {
struct Exact {
    char *p;
    size_t n;
    Exact(const uint8_t *d, size_t len) : n(len) {
        p = static_cast<char *>(malloc(len ? len : 1));
        if (len) {
            memcpy(p, d, len);
        }
    }
    ~Exact() {
        free(p);
    }
};

void fuzz_websocket(const uint8_t *d, size_t n) {
    Exact in(d, n);
    websocket::Frame frame{};
    if (websocket::parse_frame(&frame, in.p, in.n)) {
        websocket::decode(&frame, in.p, in.n);
    }
}

// Configures a Protocol from the first bytes and checks the pure framing helpers on the rest.
void fuzz_framing(const uint8_t *d, size_t n) {
    if (n < 6) {
        return;
    }
    static const char types[] = {'c', 'C', 's', 'S', 'n', 'N', 'v', 'V', 'l', 'L', 'q', 'Q', 'x'};
    Protocol protocol{};
    protocol.package_length_type = types[d[0] % sizeof(types)];
    protocol.package_length_size = swoole_type_size(protocol.package_length_type);  // as the server/client option parsing does
    protocol.package_length_offset = d[2];
    protocol.package_body_offset = d[3];
    protocol.package_max_length = (d[4] << 4) + 1;
    protocol.package_eof_len = 1 + d[5] % SW_DATA_EOF_MAXLEN;
    memset(protocol.package_eof, 'e', sizeof(protocol.package_eof));
    protocol.get_package_length = Protocol::default_length_func;
    d += 6;
    n -= 6;

    Exact in(d, n);
    ssize_t length = 0;
    uint32_t header_len = 0;
    for (size_t len = 0; len <= n; len++) {
        protocol.resolve_package_length(nullptr, in.p, len, &length, &header_len);
    }
    protocol.find_eof_end(in.p, n);
    protocol.next_eof_buffer_size(n);
}

void fuzz_mqtt(const uint8_t *d, size_t n) {
    Exact in(d, n);
    Protocol protocol{};
    PacketLength pl{in.p, static_cast<uint32_t>(n), 0};
    mqtt::get_package_length(&protocol, nullptr, &pl);
}

void fuzz_http2(const uint8_t *d, size_t n) {
    Exact in(d, n);
    Protocol protocol{};
    PacketLength pl{in.p, static_cast<uint32_t>(n), 0};
    http2::get_frame_length(&protocol, nullptr, &pl);
    uint64_t out64;
    uint16_t out16;
    http2::parse_content_length(in.p, n, UINT64_MAX, &out64);
    http2::parse_status_code(in.p, n, &out16);
}

void fuzz_http_helpers(const uint8_t *d, size_t n) {
    {
        Exact in(d, n);
        char *boundary = nullptr;
        int boundary_len = 0;
        for (size_t offset = 0; offset <= n && offset < 64; offset++) {
            http_server::parse_multipart_boundary(in.p, n, offset, &boundary, &boundary_len);
        }
    }
    {
        Exact in(d, n);
        http_server::parse_cookie(in.p, n, [](char *, size_t, char *, size_t) { return true; });
    }
    {
        // url_decode terminates the string in place, so the buffer needs one spare byte like php_url_decode().
        std::vector<char> buf(d, d + n);
        buf.push_back('\0');
        http_server::url_decode(buf.data(), n);
    }
    {
        Exact in(d, n);
        char *enc = http_server::url_encode(in.p, n);
        sw_free(enc);
    }
}

void fuzz_redis_number(const uint8_t *d, size_t n) {
    if (n == 0) {
        return;
    }
    Exact in(d, n);
    int ret;
    redis::get_number(in.p, in.p + in.n, &ret);
    redis::parse(in.p, in.n);
}

// Replays the incremental request parsing of the HTTP server (port.cc) with the input delivered in fragments.
void fuzz_http_request(const uint8_t *d, size_t n) {
    if (n < 2) {
        return;
    }
    const size_t step = 1 + d[0] % 64;
    d++;
    n--;
    String buffer(n);
    http_server::Request request;
    request.buffer_ = &buffer;
    for (size_t fed = 0; fed < n;) {
        size_t m = std::min(step, n - fed);
        buffer.append(reinterpret_cast<const char *>(d) + fed, m);
        fed += m;

        if (request.method == 0 && request.get_protocol() < 0) {
            if (request.excepted) {
                break;
            }
            continue;
        }
        if (request.method >= SW_HTTP_PRI) {
            break;
        }
        if (request.header_length_ == 0 && request.get_header_length() < 0) {
            continue;
        }
        if (!request.header_parsed) {
            request.parse_header_info();
            if (request.excepted) {
                break;
            }
        }
        if (request.chunked && request.get_chunked_body_length() < 0 && (request.excepted || request.too_large)) {
            break;
        }
        request.has_expect_header();
        request.get_header("content-type");
    }
    request.buffer_ = nullptr;
}

void fuzz_http2_settings(const uint8_t *d, size_t n) {
    Exact in(d, n);
    http2::unpack_setting_data(
        in.p, static_cast<ssize_t>(n), [](uint16_t, uint32_t) { return SW_SUCCESS; });
}

// Mirrors the inflate loop in swoole_http2_client_coro.cc / swoole_http2_server.cc, plus a deflate round-trip.
void fuzz_hpack(const uint8_t *d, size_t n) {
    if (n < 2) {
        return;
    }
    nghttp2_hd_inflater *inflater = nullptr;
    if (nghttp2_hd_inflate_new(&inflater) != 0) {
        return;
    }
    uint32_t table_size = 256u << (d[0] % 8);
    if (d[0] & 0x80) {
        nghttp2_hd_inflate_change_table_size(inflater, table_size);
    }
    size_t chunk = d[1] % 64 + 1;
    d += 2;
    n -= 2;
    while (n > 0) {
        size_t len = std::min(chunk, n);
        const uint8_t *in = d;
        size_t inlen = len;
        bool final = len == n;
        bool failed = false;
        for (;;) {
            nghttp2_nv nv;
            int flags = 0;
            ssize_t rv = nghttp2_hd_inflate_hd(inflater, &nv, &flags, const_cast<uint8_t *>(in), inlen, final);
            if (rv < 0) {
                failed = true;
                break;
            }
            in += rv;
            inlen -= rv;
            if (flags & NGHTTP2_HD_INFLATE_EMIT) {
                volatile uint8_t sink = 0;
                for (size_t i = 0; i < nv.namelen; i++) {
                    sink = sink + nv.name[i];
                }
                for (size_t i = 0; i < nv.valuelen; i++) {
                    sink = sink + nv.value[i];
                }
            }
            if (flags & NGHTTP2_HD_INFLATE_FINAL) {
                nghttp2_hd_inflate_end_headers(inflater);
                break;
            }
            if ((flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
                break;
            }
        }
        if (failed) {
            break;
        }
        d += len;
        n -= len;
    }
    nghttp2_hd_inflate_del(inflater);
}

void fuzz_hpack_roundtrip(const uint8_t *d, size_t n) {
    // Input is split into name/value pairs by 0x00 / 0x01 delimiters.
    std::vector<nghttp2_nv> nva;
    std::vector<std::vector<uint8_t>> store;
    size_t i = 0;
    while (i < n && nva.size() < 32) {
        size_t j = i;
        while (j < n && d[j] != 0) {
            j++;
        }
        store.emplace_back(d + i, d + j);
        i = j + 1;
    }
    for (size_t k = 0; k + 1 < store.size(); k += 2) {
        // Empty vectors may return a null data(), which nghttp2 passes to memcmp().
        static uint8_t empty = 0;
        nghttp2_nv nv;
        nv.name = store[k].empty() ? &empty : store[k].data();
        nv.namelen = store[k].size();
        nv.value = store[k + 1].empty() ? &empty : store[k + 1].data();
        nv.valuelen = store[k + 1].size();
        nv.flags = d[0] & NGHTTP2_NV_FLAG_NO_INDEX;
        nva.push_back(nv);
    }
    if (nva.empty()) {
        return;
    }
    nghttp2_hd_deflater *deflater = nullptr;
    nghttp2_hd_inflater *inflater = nullptr;
    if (nghttp2_hd_deflate_new(&deflater, 4096) != 0) {
        return;
    }
    if (nghttp2_hd_inflate_new(&inflater) != 0) {
        nghttp2_hd_deflate_del(deflater);
        return;
    }
    size_t bound = nghttp2_hd_deflate_bound(deflater, nva.data(), nva.size());
    std::vector<uint8_t> buf(bound);
    ssize_t len = nghttp2_hd_deflate_hd(deflater, buf.data(), buf.size(), nva.data(), nva.size());
    if (len > 0) {
        const uint8_t *in = buf.data();
        size_t inlen = len;
        size_t emitted = 0;
        for (;;) {
            nghttp2_nv nv;
            int flags = 0;
            ssize_t rv = nghttp2_hd_inflate_hd(inflater, &nv, &flags, const_cast<uint8_t *>(in), inlen, 1);
            if (rv < 0) {
                // Oversized header fields may legitimately be rejected by the inflater.
                break;
            }
            in += rv;
            inlen -= rv;
            if (flags & NGHTTP2_HD_INFLATE_EMIT) {
                emitted++;
            }
            if (flags & NGHTTP2_HD_INFLATE_FINAL) {
                nghttp2_hd_inflate_end_headers(inflater);
                break;
            }
        }
        (void) emitted;
    }
    nghttp2_hd_inflate_del(inflater);
    nghttp2_hd_deflate_del(deflater);
}
}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    swoole_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    const uint8_t *d = data + 1;
    size_t n = size - 1;
    switch (data[0] % 10) {
    case 0:
        fuzz_websocket(d, n);
        break;
    case 1:
        fuzz_framing(d, n);
        break;
    case 2:
        fuzz_mqtt(d, n);
        break;
    case 3:
        fuzz_http2(d, n);
        break;
    case 4:
        fuzz_http_helpers(d, n);
        break;
    case 5:
        fuzz_redis_number(d, n);
        break;
    case 6:
        fuzz_http_request(d, n);
        break;
    case 7:
        fuzz_http2_settings(d, n);
        break;
    case 8:
        fuzz_hpack(d, n);
        break;
    default:
        fuzz_hpack_roundtrip(d, n);
        break;
    }
    return 0;
}
