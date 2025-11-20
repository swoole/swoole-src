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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_ssl.h"

// Swoole HTTP/3 now uses OpenSSL 3.5 native QUIC support (2-layer architecture)
// Old architecture (4 layers): HTTP/3 (nghttp3) → ngtcp2 → ngtcp2_crypto_ossl → OpenSSL 3.5
// New architecture (2 layers): HTTP/3 (nghttp3) → OpenSSL 3.5 native QUIC

#ifdef SW_USE_QUIC
#include "swoole_quic_openssl.h"
#endif
