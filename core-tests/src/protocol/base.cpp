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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "test_coroutine.h"
#include "redis_client.h"
#include "swoole_redis.h"



using namespace swoole;
using namespace std;

constexpr int PKG_N = 32;
constexpr int MAX_SIZE = 128000;
constexpr int MIN_SIZE = 512;

TEST(protocol, eof) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    String pkgs[PKG_N];

    for (int i = 0; i < PKG_N; i++) {
        pkgs[i].append_random_bytes(swoole_rand(MIN_SIZE, MAX_SIZE), true);
        pkgs[i].append("\r\n");
    }

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_eof_protocol("\r\n", false);

    mutex lock;
    lock.lock();
    serv.create();

    thread t1([&]() {
        lock.lock();

        network::Client cli(SW_SOCK_TCP, false);
        EXPECT_EQ(cli.connect(&cli, TEST_HOST, port->port, 1, 0), 0);

        for (int i = 0; i < PKG_N; i++) {
            EXPECT_EQ(cli.send(&cli, pkgs[i].str, pkgs[i].length, 0), pkgs[i].length);
        }
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    int recv_count = 0;

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        //        printf("[1]LEN=%d, count=%d\n%s\n---------------------------------\n", req->info.len,  recv_count,
        //        req->data); printf("[2]LEN=%d\n%s\n---------------------------------\n", pkgs[recv_count].length,
        //        pkgs[recv_count].str);

        EXPECT_EQ(memcmp(req->data, pkgs[recv_count].str, req->info.len), 0);

        recv_count++;

        if (recv_count == PKG_N) {
            kill(serv->get_master_pid(), SIGTERM);
        }

        return SW_OK;
    };

    serv.start();

    t1.join();
}

TEST(protocol, swap_byte_order) {
    {
        EXPECT_EQ(swoole_swap_endian16(0x1234), 0x3412);
        EXPECT_EQ(swoole_swap_endian16(0x0001), 0x0100);
        EXPECT_EQ(swoole_swap_endian16(0x00FF), 0xFF00);
        EXPECT_EQ(swoole_swap_endian16(0xFF00), 0x00FF);
        EXPECT_EQ(swoole_swap_endian16(0xFFFF), 0xFFFF);
    }

    {
        EXPECT_EQ(swoole_swap_endian32(0x12345678), 0x78563412);
        EXPECT_EQ(swoole_swap_endian32(0x00000001), 0x01000000);
        EXPECT_EQ(swoole_swap_endian32(0x0000FF00), 0x00FF0000);
        EXPECT_EQ(swoole_swap_endian32(0xFF000000), 0x000000FF);
        EXPECT_EQ(swoole_swap_endian32(0xFFFFFFFF), 0xFFFFFFFF);
    }

    {
        uint16_t v = 0xABCD;
        EXPECT_EQ(swoole_swap_endian16(swoole_swap_endian16(v)), v);
    }

    {
        uint32_t v = 0xABCDEF01;
        EXPECT_EQ(swoole_swap_endian32(swoole_swap_endian32(v)), v);
    }

    {
        uint64_t val = 0x1122334455667788ULL;
        auto converted = swoole_swap_endian64(val);

        auto str = (uchar *) &converted;
        EXPECT_EQ(str[0], 0x11);
        EXPECT_EQ(str[1], 0x22);
        EXPECT_EQ(str[2], 0x33);
        EXPECT_EQ(str[3], 0x44);
        EXPECT_EQ(str[4], 0x55);
        EXPECT_EQ(str[5], 0x66);
        EXPECT_EQ(str[6], 0x77);
        EXPECT_EQ(str[7], 0x88);
    }
}

// Helper function to create binary data for testing
template <typename T>
void createBinaryData(T value, char *buffer) {
    memcpy(buffer, &value, sizeof(T));
}

TEST(protocol, unpack) {
    // Tests for 8-bit integer formats
    {
        char buffer[8];

        // Test signed char ('c')
        int8_t c_val = -42;
        createBinaryData(c_val, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), -42);

        // Test unsigned char ('C')
        uint8_t C_val = 200;
        createBinaryData(C_val, buffer);
        EXPECT_EQ(swoole_unpack('C', buffer), 200);

        // Test extreme values
        createBinaryData<int8_t>(INT8_MIN, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), INT8_MIN);

        createBinaryData<int8_t>(INT8_MAX, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), INT8_MAX);

        createBinaryData<uint8_t>(UINT8_MAX, buffer);
        EXPECT_EQ(swoole_unpack('C', buffer), UINT8_MAX);
    }

    // Tests for 16-bit integer formats
    {
        char buffer[8];

        // Test signed short ('s')
        int16_t s_val = -12345;
        createBinaryData(s_val, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), -12345);

        // Test unsigned short ('S')
        uint16_t S_val = 54321;
        createBinaryData(S_val, buffer);
        EXPECT_EQ(swoole_unpack('S', buffer), 54321);

        // Test big-endian unsigned short ('n')
        uint16_t n_val = 0x1234;
        uint16_t n_be = (n_val >> 8) | (n_val << 8);  // Convert to big-endian
        createBinaryData(n_be, buffer);
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        // Test little-endian unsigned short ('v')
        uint16_t v_val = 0x1234;
        createBinaryData(v_val, buffer);
        EXPECT_EQ(swoole_unpack('v', buffer), 0x1234);

        // Test extreme values
        createBinaryData<int16_t>(INT16_MIN, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), INT16_MIN);

        createBinaryData<int16_t>(INT16_MAX, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), INT16_MAX);

        createBinaryData<uint16_t>(UINT16_MAX, buffer);
        EXPECT_EQ(swoole_unpack('S', buffer), UINT16_MAX);
    }

    // Tests for 32-bit integer formats
    {
        char buffer[8];

        // Test signed long ('l')
        int32_t l_val = -123456789;
        createBinaryData(l_val, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), -123456789);

        // Test unsigned long ('L')
        uint32_t L_val = 3000000000;
        createBinaryData(L_val, buffer);
        EXPECT_EQ(swoole_unpack('L', buffer), 3000000000);

        // Test big-endian unsigned long ('N')
        uint32_t N_val = 0x12345678;
        uint32_t N_be =
            ((N_val & 0xFF) << 24) | ((N_val & 0xFF00) << 8) | ((N_val & 0xFF0000) >> 8) | ((N_val & 0xFF000000) >> 24);
        createBinaryData(N_be, buffer);
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        // Test little-endian unsigned long ('V')
        uint32_t V_val = 0x12345678;
        createBinaryData(V_val, buffer);
        EXPECT_EQ(swoole_unpack('V', buffer), 0x12345678);

        // Test extreme values
        createBinaryData<int32_t>(INT32_MIN, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), INT32_MIN);

        createBinaryData<int32_t>(INT32_MAX, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), INT32_MAX);

        createBinaryData<uint32_t>(UINT32_MAX, buffer);
        EXPECT_EQ(swoole_unpack('L', buffer), UINT32_MAX);
    }

    // Tests for 64-bit integer formats
    {
        char buffer[8];

        // Test signed long long ('q')
        int64_t q_val = -1234567890123456789LL;
        createBinaryData(q_val, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), -1234567890123456789LL);

        // Test unsigned long long ('Q')
        uint64_t Q_val = 10234567890123456789ULL;
        createBinaryData(Q_val, buffer);
        EXPECT_EQ(swoole_unpack('Q', buffer), 10234567890123456789ULL);

        // Test big-endian unsigned long long ('J')
        uint64_t J_val = 0x123456789ABCDEF0ULL;
        uint64_t J_be = swoole_swap_endian64(J_val);  // Use our swap function for test
        createBinaryData(J_be, buffer);
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);

        // Test little-endian unsigned long long ('P')
        uint64_t P_val = 0x123456789ABCDEF0ULL;
        createBinaryData(P_val, buffer);
        EXPECT_EQ(swoole_unpack('P', buffer), 0x123456789ABCDEF0ULL);

        // Test extreme values (be careful with signed min/max due to two's complement)
        createBinaryData<int64_t>(INT64_MIN, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), INT64_MIN);

        createBinaryData<int64_t>(INT64_MAX, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), INT64_MAX);

        // For UINT64_MAX, be aware that the return type is int64_t, so this might not work as expected
        // This test might fail due to the limitation of the return type
        createBinaryData<uint64_t>(UINT64_MAX, buffer);
        EXPECT_EQ(swoole_unpack('Q', buffer), (int64_t) UINT64_MAX);
    }

    // Tests for machine-dependent integer formats
    {
        char buffer[8];

        // Test signed integer ('i')
        int i_val = -987654321;
        createBinaryData(i_val, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), -987654321);

        // Test unsigned integer ('I')
        unsigned int I_val = 3000000000;
        createBinaryData(I_val, buffer);
        EXPECT_EQ(swoole_unpack('I', buffer), 3000000000);

        // Test extreme values
        createBinaryData<int>(INT_MIN, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), INT_MIN);

        createBinaryData<int>(INT_MAX, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), INT_MAX);

        createBinaryData<unsigned int>(UINT_MAX, buffer);
        EXPECT_EQ(swoole_unpack('I', buffer), (int64_t) UINT_MAX);
    }

    // Test for invalid format specifier
    {
        char buffer[8] = {0};

        // Test invalid format specifier
        EXPECT_EQ(swoole_unpack('x', buffer), -1);
        EXPECT_EQ(swoole_unpack('?', buffer), -1);
        EXPECT_EQ(swoole_unpack('Z', buffer), -1);
    }

    // Test for endianness-specific behavior
    {
        char buffer[8];

        // Create a test value that will be different when byte-swapped
        uint16_t test16 = 0x1234;
        uint32_t test32 = 0x12345678;
        uint64_t test64 = 0x123456789ABCDEF0ULL;

        // Test that 'n' and 'v' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        buffer[0] = 0x34;
        buffer[1] = 0x12;
        EXPECT_EQ(swoole_unpack('v', buffer), 0x1234);

        // Test that 'N' and 'V' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        buffer[2] = 0x56;
        buffer[3] = 0x78;
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        buffer[0] = 0x78;
        buffer[1] = 0x56;
        buffer[2] = 0x34;
        buffer[3] = 0x12;
        EXPECT_EQ(swoole_unpack('V', buffer), 0x12345678);

        // Test that 'J' and 'P' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        buffer[2] = 0x56;
        buffer[3] = 0x78;
        buffer[4] = 0x9A;
        buffer[5] = 0xBC;
        buffer[6] = 0xDE;
        buffer[7] = 0xF0;
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);

        buffer[0] = 0xF0;
        buffer[1] = 0xDE;
        buffer[2] = 0xBC;
        buffer[3] = 0x9A;
        buffer[4] = 0x78;
        buffer[5] = 0x56;
        buffer[6] = 0x34;
        buffer[7] = 0x12;
        EXPECT_EQ(swoole_unpack('P', buffer), 0x123456789ABCDEF0ULL);
    }

    {
        char buffer[8];

        // Test that 'n' format uses ntohs() correctly
        uint16_t test16 = 0x1234;
        uint16_t be16 = htons(test16);  // Convert to network byte order
        createBinaryData(be16, buffer);
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        // Test that 'N' format uses ntohl() correctly
        uint32_t test32 = 0x12345678;
        uint32_t be32 = htonl(test32);  // Convert to network byte order
        createBinaryData(be32, buffer);
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        // Test that 'J' format uses swoole_ntoh64() correctly
        uint64_t test64 = 0x123456789ABCDEF0ULL;
        uint64_t be64 = swoole_hton64(test64);  // Convert to network byte order
        createBinaryData(be64, buffer);
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);
    }
}

TEST(protocol, hton64) {
    {
        uint64_t val = 0x1122334455667788ULL;
        uint64_t converted = swoole_hton64(val);

        auto str = (uchar *) &converted;
        EXPECT_EQ(str[0], 0x11);
        EXPECT_EQ(str[1], 0x22);
        EXPECT_EQ(str[2], 0x33);
        EXPECT_EQ(str[3], 0x44);
        EXPECT_EQ(str[4], 0x55);
        EXPECT_EQ(str[5], 0x66);
        EXPECT_EQ(str[6], 0x77);
        EXPECT_EQ(str[7], 0x88);

        uint64_t reversed = swoole_ntoh64(converted);
        EXPECT_EQ(reversed, val);
    }

    {
        uint64_t min_val = 0ULL;
        uint64_t min_converted = swoole_hton64(min_val);

        auto min_str = (unsigned char *) &min_converted;
        for (int i = 0; i < 8; i++) {
            EXPECT_EQ(min_str[i], 0x00) << "Byte " << i << " should be 0x00";
        }

        EXPECT_EQ(swoole_ntoh64(min_converted), min_val);

        // 测试最大值
        uint64_t max_val = UINT64_MAX;
        uint64_t max_converted = swoole_hton64(max_val);

        auto max_str = (unsigned char *) &max_converted;
        for (int i = 0; i < 8; i++) {
            EXPECT_EQ(max_str[i], 0xFF) << "Byte " << i << " should be 0xFF";
        }

        EXPECT_EQ(swoole_ntoh64(max_converted), max_val);
    }

    {
        uint64_t alt_pattern = 0xAAAAAAAAAAAAAAAAULL;
        uint64_t alt_converted = swoole_hton64(alt_pattern);
        EXPECT_EQ(swoole_ntoh64(alt_converted), alt_pattern);

        uint64_t alt_pattern2 = 0x5555555555555555ULL;
        uint64_t alt_converted2 = swoole_hton64(alt_pattern2);
        EXPECT_EQ(swoole_ntoh64(alt_converted2), alt_pattern2);

        // 测试单字节模式
        for (int i = 0; i < 8; i++) {
            uint64_t single_byte = 0xFFULL << (i * 8);
            uint64_t converted = swoole_hton64(single_byte);
            EXPECT_EQ(swoole_ntoh64(converted), single_byte) << "Failed for byte position " << i;
        }
    }

    {
        for (int i = 0; i < 100; i++) {
            uint64_t random_val = swoole_random_int();
            uint64_t converted = swoole_hton64(random_val);
            uint64_t reversed = swoole_ntoh64(converted);

            EXPECT_EQ(reversed, random_val) << "Failed for random value: 0x" << std::hex << random_val;
        }
    }

    {
        uint64_t test_val = 0x0102030405060708ULL;
        uint64_t converted = swoole_hton64(test_val);

        auto bytes = (unsigned char *) &converted;

        EXPECT_EQ(bytes[0], 0x01);
        EXPECT_EQ(bytes[1], 0x02);
        EXPECT_EQ(bytes[2], 0x03);
        EXPECT_EQ(bytes[3], 0x04);
        EXPECT_EQ(bytes[4], 0x05);
        EXPECT_EQ(bytes[5], 0x06);
        EXPECT_EQ(bytes[6], 0x07);
        EXPECT_EQ(bytes[7], 0x08);
    }

    {
        for (int i = 0; i < 100; i++) {
            uint64_t val = swoole_random_int();
            EXPECT_EQ(swoole_ntoh64(swoole_hton64(val)), val) << "hton64->ntoh64 failed for 0x" << std::hex << val;
            EXPECT_EQ(swoole_hton64(swoole_ntoh64(val)), val) << "ntoh64->hton64 failed for 0x" << std::hex << val;
        }
    }
}
