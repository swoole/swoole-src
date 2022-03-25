/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http:// www.apache.org/licenses/LICENSE-2.0.html                     |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Twosee  <twose@qq.com>                                       |
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#include "php_swoole_mysql_proto.h"

using namespace swoole::mysql;

namespace swoole {
namespace mysql {
struct charset_t {
    uint nr;
    const char *name;
    const char *collation;
};

char get_charset(const char *name) {
    static const charset_t charsets[] = {
        {1, "big5", "big5_chinese_ci"},
        {3, "dec8", "dec8_swedish_ci"},
        {4, "cp850", "cp850_general_ci"},
        {6, "hp8", "hp8_english_ci"},
        {7, "koi8r", "koi8r_general_ci"},
        {8, "latin1", "latin1_swedish_ci"},
        {5, "latin1", "latin1_german1_ci"},
        {9, "latin2", "latin2_general_ci"},
        {2, "latin2", "latin2_czech_cs"},
        {10, "swe7", "swe7_swedish_ci"},
        {11, "ascii", "ascii_general_ci"},
        {12, "ujis", "ujis_japanese_ci"},
        {13, "sjis", "sjis_japanese_ci"},
        {16, "hebrew", "hebrew_general_ci"},
        {17, "filename", "filename"},
        {18, "tis620", "tis620_thai_ci"},
        {19, "euckr", "euckr_korean_ci"},
        {21, "latin2", "latin2_hungarian_ci"},
        {27, "latin2", "latin2_croatian_ci"},
        {22, "koi8u", "koi8u_general_ci"},
        {24, "gb2312", "gb2312_chinese_ci"},
        {25, "greek", "greek_general_ci"},
        {26, "cp1250", "cp1250_general_ci"},
        {28, "gbk", "gbk_chinese_ci"},
        {30, "latin5", "latin5_turkish_ci"},
        {31, "latin1", "latin1_german2_ci"},
        {15, "latin1", "latin1_danish_ci"},
        {32, "armscii8", "armscii8_general_ci"},
        {33, "utf8", "utf8_general_ci"},
        {35, "ucs2", "ucs2_general_ci"},
        {36, "cp866", "cp866_general_ci"},
        {37, "keybcs2", "keybcs2_general_ci"},
        {38, "macce", "macce_general_ci"},
        {39, "macroman", "macroman_general_ci"},
        {40, "cp852", "cp852_general_ci"},
        {41, "latin7", "latin7_general_ci"},
        {20, "latin7", "latin7_estonian_cs"},
        {57, "cp1256", "cp1256_general_ci"},
        {59, "cp1257", "cp1257_general_ci"},
        {63, "binary", "binary"},
        {97, "eucjpms", "eucjpms_japanese_ci"},
        {29, "cp1257", "cp1257_lithuanian_ci"},
        {31, "latin1", "latin1_german2_ci"},
        {34, "cp1250", "cp1250_czech_cs"},
        {42, "latin7", "latin7_general_cs"},
        {43, "macce", "macce_bin"},
        {44, "cp1250", "cp1250_croatian_ci"},
        {45, "utf8mb4", "utf8mb4_general_ci"},
        {46, "utf8mb4", "utf8mb4_bin"},
        {47, "latin1", "latin1_bin"},
        {48, "latin1", "latin1_general_ci"},
        {49, "latin1", "latin1_general_cs"},
        {51, "cp1251", "cp1251_general_ci"},
        {14, "cp1251", "cp1251_bulgarian_ci"},
        {23, "cp1251", "cp1251_ukrainian_ci"},
        {50, "cp1251", "cp1251_bin"},
        {52, "cp1251", "cp1251_general_cs"},
        {53, "macroman", "macroman_bin"},
        {54, "utf16", "utf16_general_ci"},
        {55, "utf16", "utf16_bin"},
        {56, "utf16le", "utf16le_general_ci"},
        {58, "cp1257", "cp1257_bin"},
        {60, "utf32", "utf32_general_ci"},
        {61, "utf32", "utf32_bin"},
        {62, "utf16le", "utf16le_bin"},
        {64, "armscii8", "armscii8_bin"},
        {65, "ascii", "ascii_bin"},
        {66, "cp1250", "cp1250_bin"},
        {67, "cp1256", "cp1256_bin"},
        {68, "cp866", "cp866_bin"},
        {69, "dec8", "dec8_bin"},
        {70, "greek", "greek_bin"},
        {71, "hebrew", "hebrew_bin"},
        {72, "hp8", "hp8_bin"},
        {73, "keybcs2", "keybcs2_bin"},
        {74, "koi8r", "koi8r_bin"},
        {75, "koi8u", "koi8u_bin"},
        {77, "latin2", "latin2_bin"},
        {78, "latin5", "latin5_bin"},
        {79, "latin7", "latin7_bin"},
        {80, "cp850", "cp850_bin"},
        {81, "cp852", "cp852_bin"},
        {82, "swe7", "swe7_bin"},
        {83, "utf8", "utf8_bin"},
        {84, "big5", "big5_bin"},
        {85, "euckr", "euckr_bin"},
        {86, "gb2312", "gb2312_bin"},
        {87, "gbk", "gbk_bin"},
        {88, "sjis", "sjis_bin"},
        {89, "tis620", "tis620_bin"},
        {90, "ucs2", "ucs2_bin"},
        {91, "ujis", "ujis_bin"},
        {92, "geostd8", "geostd8_general_ci"},
        {93, "geostd8", "geostd8_bin"},
        {94, "latin1", "latin1_spanish_ci"},
        {95, "cp932", "cp932_japanese_ci"},
        {96, "cp932", "cp932_bin"},
        {97, "eucjpms", "eucjpms_japanese_ci"},
        {98, "eucjpms", "eucjpms_bin"},
        {99, "cp1250", "cp1250_polish_ci"},
        {128, "ucs2", "ucs2_unicode_ci"},
        {129, "ucs2", "ucs2_icelandic_ci"},
        {130, "ucs2", "ucs2_latvian_ci"},
        {131, "ucs2", "ucs2_romanian_ci"},
        {132, "ucs2", "ucs2_slovenian_ci"},
        {133, "ucs2", "ucs2_polish_ci"},
        {134, "ucs2", "ucs2_estonian_ci"},
        {135, "ucs2", "ucs2_spanish_ci"},
        {136, "ucs2", "ucs2_swedish_ci"},
        {137, "ucs2", "ucs2_turkish_ci"},
        {138, "ucs2", "ucs2_czech_ci"},
        {139, "ucs2", "ucs2_danish_ci"},
        {140, "ucs2", "ucs2_lithuanian_ci"},
        {141, "ucs2", "ucs2_slovak_ci"},
        {142, "ucs2", "ucs2_spanish2_ci"},
        {143, "ucs2", "ucs2_roman_ci"},
        {144, "ucs2", "ucs2_persian_ci"},
        {145, "ucs2", "ucs2_esperanto_ci"},
        {146, "ucs2", "ucs2_hungarian_ci"},
        {147, "ucs2", "ucs2_sinhala_ci"},
        {148, "ucs2", "ucs2_german2_ci"},
        {149, "ucs2", "ucs2_croatian_ci"},
        {150, "ucs2", "ucs2_unicode_520_ci"},
        {151, "ucs2", "ucs2_vietnamese_ci"},
        {160, "utf32", "utf32_unicode_ci"},
        {161, "utf32", "utf32_icelandic_ci"},
        {162, "utf32", "utf32_latvian_ci"},
        {163, "utf32", "utf32_romanian_ci"},
        {164, "utf32", "utf32_slovenian_ci"},
        {165, "utf32", "utf32_polish_ci"},
        {166, "utf32", "utf32_estonian_ci"},
        {167, "utf32", "utf32_spanish_ci"},
        {168, "utf32", "utf32_swedish_ci"},
        {169, "utf32", "utf32_turkish_ci"},
        {170, "utf32", "utf32_czech_ci"},
        {171, "utf32", "utf32_danish_ci"},
        {172, "utf32", "utf32_lithuanian_ci"},
        {173, "utf32", "utf32_slovak_ci"},
        {174, "utf32", "utf32_spanish2_ci"},
        {175, "utf32", "utf32_roman_ci"},
        {176, "utf32", "utf32_persian_ci"},
        {177, "utf32", "utf32_esperanto_ci"},
        {178, "utf32", "utf32_hungarian_ci"},
        {179, "utf32", "utf32_sinhala_ci"},
        {180, "utf32", "utf32_german2_ci"},
        {181, "utf32", "utf32_croatian_ci"},
        {182, "utf32", "utf32_unicode_520_ci"},
        {183, "utf32", "utf32_vietnamese_ci"},
        {192, "utf8", "utf8_unicode_ci"},
        {193, "utf8", "utf8_icelandic_ci"},
        {194, "utf8", "utf8_latvian_ci"},
        {195, "utf8", "utf8_romanian_ci"},
        {196, "utf8", "utf8_slovenian_ci"},
        {197, "utf8", "utf8_polish_ci"},
        {198, "utf8", "utf8_estonian_ci"},
        {199, "utf8", "utf8_spanish_ci"},
        {200, "utf8", "utf8_swedish_ci"},
        {201, "utf8", "utf8_turkish_ci"},
        {202, "utf8", "utf8_czech_ci"},
        {203, "utf8", "utf8_danish_ci"},
        {204, "utf8", "utf8_lithuanian_ci"},
        {205, "utf8", "utf8_slovak_ci"},
        {206, "utf8", "utf8_spanish2_ci"},
        {207, "utf8", "utf8_roman_ci"},
        {208, "utf8", "utf8_persian_ci"},
        {209, "utf8", "utf8_esperanto_ci"},
        {210, "utf8", "utf8_hungarian_ci"},
        {211, "utf8", "utf8_sinhala_ci"},
        {212, "utf8", "utf8_german2_ci"},
        {213, "utf8", "utf8_croatian_ci"},
        {214, "utf8", "utf8_unicode_520_ci"},
        {215, "utf8", "utf8_vietnamese_ci"},
        {224, "utf8mb4", "utf8mb4_unicode_ci"},
        {225, "utf8mb4", "utf8mb4_icelandic_ci"},
        {226, "utf8mb4", "utf8mb4_latvian_ci"},
        {227, "utf8mb4", "utf8mb4_romanian_ci"},
        {228, "utf8mb4", "utf8mb4_slovenian_ci"},
        {229, "utf8mb4", "utf8mb4_polish_ci"},
        {230, "utf8mb4", "utf8mb4_estonian_ci"},
        {231, "utf8mb4", "utf8mb4_spanish_ci"},
        {232, "utf8mb4", "utf8mb4_swedish_ci"},
        {233, "utf8mb4", "utf8mb4_turkish_ci"},
        {234, "utf8mb4", "utf8mb4_czech_ci"},
        {235, "utf8mb4", "utf8mb4_danish_ci"},
        {236, "utf8mb4", "utf8mb4_lithuanian_ci"},
        {237, "utf8mb4", "utf8mb4_slovak_ci"},
        {238, "utf8mb4", "utf8mb4_spanish2_ci"},
        {239, "utf8mb4", "utf8mb4_roman_ci"},
        {240, "utf8mb4", "utf8mb4_persian_ci"},
        {241, "utf8mb4", "utf8mb4_esperanto_ci"},
        {242, "utf8mb4", "utf8mb4_hungarian_ci"},
        {243, "utf8mb4", "utf8mb4_sinhala_ci"},
        {244, "utf8mb4", "utf8mb4_german2_ci"},
        {245, "utf8mb4", "utf8mb4_croatian_ci"},
        {246, "utf8mb4", "utf8mb4_unicode_520_ci"},
        {247, "utf8mb4", "utf8mb4_vietnamese_ci"},
        {248, "gb18030", "gb18030_chinese_ci"},
        {249, "gb18030", "gb18030_bin"},
        {254, "utf8", "utf8_general_cs"},
        {0, nullptr, nullptr},
    };
    const charset_t *c = charsets;
    while (c[0].nr) {
        if (!strcasecmp(c->name, name)) {
            return c->nr;
        }
        ++c;
    }
    return -1;
}

// clang-format off
uint8_t get_static_type_size(uint8_t type)
{
    static const uint8_t map[] =
    {
        0,                // SW_MYSQL_TYPE_DECIMAL   0
        sizeof(int8_t),   // SW_MYSQL_TYPE_TINY      1
        sizeof(int16_t),  // SW_MYSQL_TYPE_SHORT     2
        sizeof(int32_t),  // SW_MYSQL_TYPE_LONG      3
        sizeof(float),    // SW_MYSQL_TYPE_FLOAT     4
        sizeof(double),   // SW_MYSQL_TYPE_DOUBLE    5
        0,                // SW_MYSQL_TYPE_NULL      6
        0,                // SW_MYSQL_TYPE_TIMESTAMP 7
        sizeof(int64_t),  // SW_MYSQL_TYPE_LONGLONG  8
        sizeof(int32_t),  // SW_MYSQL_TYPE_INT24     9
        0,                // SW_MYSQL_TYPE_DATE      10
        0,                // SW_MYSQL_TYPE_TIME      11
        0,                // SW_MYSQL_TYPE_DATETIME  12
        sizeof(int16_t),  // SW_MYSQL_TYPE_YEAR      13
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0
    };
    SW_ASSERT(sizeof(map) == UINT8_MAX + 1);
    return map[type];
}
// clang-format on

static uint32_t sha1_password_with_nonce(char *buf, const char *nonce, const char *password) {
    char hash_0[20] = {};
    php_swoole_sha1(password, strlen(password), (uchar *) hash_0);

    char hash_1[20] = {};
    php_swoole_sha1(hash_0, sizeof(hash_0), (uchar *) hash_1);

    char str[40];
    memcpy(str, nonce, 20);
    memcpy(str + 20, hash_1, 20);

    char hash_2[20];
    php_swoole_sha1(str, sizeof(str), (uchar *) hash_2);

    char hash_3[20];

    int *a = (int *) hash_2;
    int *b = (int *) hash_0;
    int *c = (int *) hash_3;

    int i;
    for (i = 0; i < 5; i++) {
        c[i] = a[i] ^ b[i];
    }
    memcpy(buf, hash_3, 20);
    return 20;
}

static uint32_t sha256_password_with_nonce(char *buf, const char *nonce, const char *password) {
    // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), nonce))
    char hashed[32], double_hashed[32];
    php_swoole_sha256(password, strlen(password), (unsigned char *) hashed);
    php_swoole_sha256(hashed, 32, (unsigned char *) double_hashed);
    char combined[32 + SW_MYSQL_NONCE_LENGTH];  // double-hashed + nonce
    memcpy(combined, double_hashed, 32);
    memcpy(combined + 32, nonce, SW_MYSQL_NONCE_LENGTH);
    char xor_bytes[32];
    php_swoole_sha256(combined, 32 + SW_MYSQL_NONCE_LENGTH, (unsigned char *) xor_bytes);
    int i;
    for (i = 0; i < 32; i++) {
        hashed[i] ^= xor_bytes[i];
    }
    memcpy(buf, hashed, 32);
    return 32;
}

/** @return: password length */
static sw_inline uint32_t mysql_auth_encrypt_dispatch(char *buf,
                                                      const std::string auth_plugin_name,
                                                      const char *nonce,
                                                      const char *password) {
    if (auth_plugin_name.length() == 0 || auth_plugin_name == "mysql_native_password") {
        // mysql_native_password is default
        return sha1_password_with_nonce(buf, nonce, password);
    } else if (auth_plugin_name == "caching_sha2_password") {
        return sha256_password_with_nonce(buf, nonce, password);
    } else {
        swoole_warning("Unknown auth plugin: %s", auth_plugin_name.c_str());
        return 0;
    }
}

eof_packet::eof_packet(const char *data) : server_packet(data) {
    swMysqlPacketDump(header.length, header.number, data, "EOF_Packet");
    // EOF_Packet = Packet header (4 bytes) + 0xFE + warning(2byte) + status(2byte)
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [fe] EOF header
    data += 1;
    // int<2>   warnings    number of warnings
    warning_count = sw_mysql_uint2korr2korr(data);
    data += 2;
    // int<2>   status_flags    Status Flags
    server_status = sw_mysql_uint2korr2korr(data);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "EOF_Packet, warnings=%u, status_code=%u", warning_count, server_status.status);
}

ok_packet::ok_packet(const char *data) : server_packet(data) {
    swMysqlPacketDump(header.length, header.number, data, "OK_Packet");
    bool nul;
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [00] or [fe] the OK packet header
    data += 1;
    // int<lenenc>  affected_rows   affected rows
    data += read_lcb(data, &affected_rows, &nul);
    // int<lenenc>  last_insert_id  last insert id
    data += read_lcb(data, &last_insert_id, &nul);
    // int<2>   status_flags    status Flags
    server_status = sw_mysql_uint2korr2korr(data);
    data += 2;
    // int<2>   warnings    number of warnings
    warning_count = sw_mysql_uint2korr2korr(data);
    // p += 2;
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "OK_Packet, affected_rows=%" PRIu64 ", insert_id=%" PRIu64 ", status_flags=0x%08x, warnings=%u",
               affected_rows,
               last_insert_id,
               server_status.status,
               warning_count);
}

err_packet::err_packet(const char *data) : server_packet(data) {
    swMysqlPacketDump(header.length, header.number, data, "ERR_Packet");
    // ERR Packet = Packet header (4 bytes) + ERR Payload
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // int<1>   header  [ff] header of the ERR packet
    data += 1;
    // int<2>   error_code  error-code
    code = sw_mysql_uint2korr2korr(data);
    data += 2;
    // string[1]    sql_state_marker    # marker of the SQL State
    data += 1;
    // string[5]    sql_state   SQL State
    memcpy(sql_state, data, 5);
    sql_state[5] = '\0';
    data += 5;
    // string<EOF>  error_message   human readable error message
    msg = std::string(data, header.length - 9);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "ERR_Packet, error_code=%u, sql_state=%s, status_msg=[%s]",
               code,
               sql_state,
               msg.c_str());
};

greeting_packet::greeting_packet(const char *data) : server_packet(data) {
    swMysqlPacketDump(header.length, header.number, data, "Protocol::HandshakeGreeting");
    /**
    1              [0a] protocol version
    string[NUL]    server version
    4              connection id
    string[8]      auth-plugin-data-part-1
    1              [00] filler
    2              capability flags (lower 2 bytes)
      if more data in the packet:
    1              character set
    2              status flags
    2              capability flags (upper 2 bytes)
      if capabilities & CLIENT_PLUGIN_AUTH {
    1              length of auth-plugin-data
      } else {
    1              [00]
      }
    string[10]     reserved (all [00])
      if capabilities & CLIENT_SECURE_CONNECTION {
    string[$len]   auth-plugin-data-part-2 ($len=MAX(13, length of auth-plugin-data - 8))
      if capabilities & CLIENT_PLUGIN_AUTH {
    string[NUL]    auth-plugin name
      }
    */
    const char *p = data + SW_MYSQL_PACKET_HEADER_SIZE;
    // 1              [0a] protocol version
    protocol_version = *p;
    p++;
    // x              server version
    server_version = std::string(p);
    p += server_version.length() + 1;
    // 4              connection id
    connection_id = *((int *) p);
    p += 4;
    // string[8]      auth-plugin-data-part-1
    memcpy(auth_plugin_data, p, 8);
    p += 8;
    // 1              [00] filler
    filler = *p;
    p += 1;
    // 2              capability flags (lower 2 bytes)
    memcpy(((char *) (&capability_flags)), p, 2);
    p += 2;

    if (p < data + header.length) {
        // 1              character set
        charset = *p;
        p += 1;
        // 2              status flags
        memcpy(&status_flags, p, 2);
        p += 2;
        // 2              capability flags (upper 2 bytes)
        memcpy(((char *) (&capability_flags) + 2), p, 2);
        p += 2;
        // 1              auth plugin data length
        auth_plugin_data_length = (uint8_t) *p;
        p += 1;
        // x              reserved
        memcpy(&reserved, p, sizeof(reserved));
        p += sizeof(reserved);
        if (capability_flags & SW_MYSQL_CLIENT_SECURE_CONNECTION) {
            uint8_t len = SW_MAX(13, auth_plugin_data_length - 8);
            memcpy(auth_plugin_data + 8, p, len);
            p += len;
        }
        if (capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH) {
            auth_plugin_name = std::string(p, strlen(p));
            swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "use %s auth plugin", auth_plugin_name.c_str());
        }
    }
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "Server protocol=%d, version=%s, connection_id=%d, capabilites=0x%08x, status=%u, auth_plugin_name=%s, "
               "auth_plugin_data=L%u[%s]",
               protocol_version,
               server_version.c_str(),
               connection_id,
               capability_flags,
               status_flags.status,
               auth_plugin_name.c_str(),
               auth_plugin_data_length,
               auth_plugin_data);
};

login_packet::login_packet(greeting_packet *greeting_packet,
                           const std::string &user,
                           const std::string &password,
                           std::string database,
                           char charset) {
    char *p = data.body;
    uint32_t tint;
    // capability flags, CLIENT_PROTOCOL_41 always set
    tint = SW_MYSQL_CLIENT_LONG_PASSWORD | SW_MYSQL_CLIENT_PROTOCOL_41 | SW_MYSQL_CLIENT_SECURE_CONNECTION |
           SW_MYSQL_CLIENT_CONNECT_WITH_DB | SW_MYSQL_CLIENT_PLUGIN_AUTH | SW_MYSQL_CLIENT_MULTI_RESULTS;
    memcpy(p, &tint, sizeof(tint));
    p += sizeof(tint);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "Client capabilites=0x%08x", tint);
    // max-packet size
    tint = 300;
    memcpy(p, &tint, sizeof(tint));
    p += sizeof(tint);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "Client max packet=%u", tint);
    // use the server character_set when the character_set is not set.
    *p = charset ? charset : greeting_packet->charset;
    p += 1;
    // string[23]     reserved (all [0])
    p += 23;
    // string[NUL]    username
    strcpy(p, user.c_str());
    p += (user.length() + 1);
    // string[NUL]    password
    if (password.length() > 0) {
        *p = mysql_auth_encrypt_dispatch(
            p + 1, greeting_packet->auth_plugin_name, greeting_packet->auth_plugin_data, password.c_str());
    } else {
        *p = 0;
    }
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "Client charset=%u, user=%s, password=%s, hased=L%d[%.*s], database=%s, auth_plugin_name=%s",
               charset,
               user.c_str(),
               password.c_str(),
               (int) *p,
               (int) *p,
               p + 1,
               database.c_str(),
               greeting_packet->auth_plugin_name.c_str());
    p += (((uint32_t) *p) + 1);
    // string[NUL]    database
    strcpy(p, database.c_str());
    p += (database.length() + 1);
    // string[NUL]    auth plugin name
    strcpy(p, greeting_packet->auth_plugin_name.c_str());
    p += (greeting_packet->auth_plugin_name.length() + 1);
    // packet header
    set_header(p - data.body, greeting_packet->header.number + 1);
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::HandshakeLogin");
}

auth_switch_request_packet::auth_switch_request_packet(const char *data) : server_packet(data) {
    swMysqlPacketDump(header.length, header.number, data, "Protocol::AuthSwitchRequest");
    // 4 header
    data += SW_MYSQL_PACKET_HEADER_SIZE;
    // 1 type
    data += 1;
    // string[NUL] auth_method_name
    auth_method_name = std::string(data);
    data += (auth_method_name.length() + 1);
    // string[NUL] auth_method_data
    strcpy(auth_method_data, data);
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "auth switch plugin name=%s", auth_method_name.c_str());
}

auth_switch_response_packet::auth_switch_response_packet(auth_switch_request_packet *req, const std::string &password) {
    // if auth switch is triggered, password can't be empty
    // create auth switch response packet
    set_header(mysql_auth_encrypt_dispatch(data.body, req->auth_method_name, req->auth_method_data, password.c_str()),
               req->header.number + 1);
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::AuthSignatureResponse");
}

//  Caching sha2 authentication. Public key request and send encrypted password
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
auth_signature_response_packet::auth_signature_response_packet(raw_data_packet *raw_data_pakcet,
                                                               const std::string &password,
                                                               const char *auth_plugin_data) {
#ifndef SW_MYSQL_RSA_SUPPORT
    {
        swoole_warning(SW_MYSQL_NO_RSA_ERROR);
#else
    if (0) {
    _error:
#endif
        data.body[0] = SW_MYSQL_AUTH_SIGNATURE_ERROR;
        set_header(1, raw_data_pakcet->header.number + 1);
        return;
    }
#ifdef SW_MYSQL_RSA_SUPPORT
    const char *tmp = raw_data_pakcet->body;
    uint32_t rsa_public_key_length = raw_data_pakcet->header.length;
    while (tmp[0] != 0x2d) {
        tmp++;  // ltrim
        rsa_public_key_length--;
    }
    char rsa_public_key[rsa_public_key_length + 1];  // rsa + '\0'
    memcpy((char *) rsa_public_key, tmp, rsa_public_key_length);
    rsa_public_key[rsa_public_key_length] = '\0';
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "rsa_public_key_length=%d;\nrsa_public_key=[%.*s]",
               rsa_public_key_length,
               rsa_public_key_length,
               rsa_public_key);

    size_t password_bytes_length = password.length() + 1;
    unsigned char password_bytes[password_bytes_length];
    // copy NUL terminator to password to stack
    strcpy((char *) password_bytes, password.c_str());
    // XOR the password bytes with the challenge
    for (size_t i = 0; i < password_bytes_length; i++)  // include '\0' byte
    {
        password_bytes[i] ^= auth_plugin_data[i % SW_MYSQL_NONCE_LENGTH];
    }

    // prepare RSA public key
    BIO *bio = nullptr;
    RSA *public_rsa = nullptr;
    if (sw_unlikely((bio = BIO_new_mem_buf((void *) rsa_public_key, -1)) == nullptr)) {
        swoole_warning("BIO_new_mem_buf publicKey error!");
        goto _error;
    }
    // PEM_read_bio_RSA_PUBKEY
    ERR_clear_error();
    if (sw_unlikely((public_rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr)) == nullptr)) {
        char err_buf[512];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swoole_warning("[PEM_read_bio_RSA_PUBKEY ERROR]: %s", err_buf);
        goto _error;
    }
    BIO_free_all(bio);
    // encrypt with RSA public key
    int rsa_len = RSA_size(public_rsa);
    unsigned char encrypt_msg[rsa_len];
    // RSA_public_encrypt
    ERR_clear_error();
    size_t flen = rsa_len - 42;
    flen = password_bytes_length > flen ? flen : password_bytes_length;
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT, "rsa_len=%d", rsa_len);
    if (sw_unlikely(RSA_public_encrypt(flen,
                                       (const unsigned char *) password_bytes,
                                       (unsigned char *) encrypt_msg,
                                       public_rsa,
                                       RSA_PKCS1_OAEP_PADDING) < 0)) {
        char err_buf[512];
        ERR_load_crypto_strings();
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        swoole_warning("[RSA_public_encrypt ERROR]: %s", err_buf);
        goto _error;
    }
    RSA_free(public_rsa);
    memcpy(data.body, (char *) encrypt_msg, rsa_len);  // copy rsa to buf
    set_header(rsa_len, raw_data_pakcet->header.number + 1);
    swMysqlPacketDump(get_length(), get_number(), get_data(), "Protocol::AuthSignatureResponse");
#endif
}

void field_packet::parse(const char *data) {
    server_packet::parse(data);
    bool nul = false;
    char *p = body = new char[header.length];
    memcpy(body, data + SW_MYSQL_PACKET_HEADER_SIZE, header.length);
    // catalog
    p += read_lcb(p, &catalog_length, &nul);
    catalog = p;
    p += catalog_length;
    // database
    p += read_lcb(p, &database_length, &nul);
    database = p;
    p += database_length;
    // table
    p += read_lcb(p, &table_length, &nul);
    table = p;
    p += table_length;
    // origin table
    p += read_lcb(p, &org_table_length, &nul);
    org_table = p;
    p += org_table_length;
    // name
    p += read_lcb(p, &name_length, &nul);
    name = p;
    p += name_length;
    // origin table
    p += read_lcb(p, &org_name_length, &nul);
    org_name = p;
    p += org_name_length;
    // filler
    p += 1;
    // charset
    charset = sw_mysql_uint2korr2korr(p);
    p += 2;
    // binary length
    length = sw_mysql_uint2korr4korr(p);
    p += 4;
    // field type
    type = (uint8_t) *p;
    p += 1;
    // flags
    flags = sw_mysql_uint2korr2korr(p);
    p += 2;
    /* decimals */
    decimals = *p;
    p += 1;
    /* filler */
    p += 2;
    /* default - a priori facultatif */
    if (p < body + header.length) {
        p += read_lcb(p, &def_length, &nul);
        def = p;
        p += def_length;
    }
    swMysqlPacketDump(header.length, header.number, data, (*name == '?' ? "Protocol::Param" : "Protocol::Field"));
    swoole_trace_log(SW_TRACE_MYSQL_CLIENT,
               "catalog=%.*s, database=%.*s, table=%.*s, org_table=%.*s, name=%.*s, org_name=%.*s,"
               "charset=%u, binary_length=%" PRIu64 ", type=%u, flags=0x%08x, decimals=%u, def=[%.*s]",
               catalog_length,
               catalog,
               database_length,
               database,
               table_length,
               table,
               org_table_length,
               org_table,
               name_length,
               name,
               org_name_length,
               org_name,
               charset,
               length,
               type,
               flags,
               decimals,
               def_length,
               def);
}
}  // namespace mysql
}  // namespace swoole
