#include "test_core.h"
#include "swoole_mqtt.h"

using namespace swoole;

TEST(mqtt_protocol, remaining_length_boundaries_and_fragments) {
    const std::pair<std::string, uint32_t> cases[] = {
        {std::string("\x30\x00", 2), 0},
        {std::string("\x30\x7f", 2), 127},
        {std::string("\x30\x80\x01", 3), 128},
        {std::string("\x30\xff\x7f", 3), 16383},
        {std::string("\x30\x80\x80\x01", 4), 16384},
        {std::string("\x30\xff\xff\x7f", 4), 2097151},
        {std::string("\x30\x80\x80\x80\x01", 5), 2097152},
        {std::string("\x30\xff\xff\xff\x7f", 5), SW_MQTT_MAX_PAYLOAD_SIZE},
    };
    Protocol protocol{};
    mqtt::set_protocol(&protocol);
    ASSERT_EQ(protocol.package_length_offset, 1);
    ASSERT_EQ(protocol.package_length_size, SW_MQTT_MAX_LENGTH_SIZE);
    ASSERT_EQ(protocol.get_package_length, mqtt::get_package_length);

    for (const auto &item : cases) {
        SCOPED_TRACE(item.second);
        // Supply every prefix, including a fixed header without a length byte. The parser
        // must wait for the final continuation byte without inspecting unreceived bytes.
        for (size_t size = 1; size < item.first.size(); size++) {
            PacketLength length{item.first.data(), static_cast<uint32_t>(size)};
            EXPECT_EQ(protocol.get_package_length(&protocol, nullptr, &length), 0);
        }
        PacketLength length{item.first.data(), static_cast<uint32_t>(item.first.size())};
        EXPECT_EQ(protocol.get_package_length(&protocol, nullptr, &length), item.second + item.first.size());
    }
}

TEST(mqtt_protocol, rejects_fifth_remaining_length_byte) {
    Protocol protocol{};
    const int saved_error = swoole_get_last_error();
    for (const auto &header : {std::string("\x30\x80\x80\x80\x80", 5), std::string("\x30\xff\xff\xff\xff\x00", 6)}) {
        PacketLength length{header.data(), static_cast<uint32_t>(header.size())};
        EXPECT_EQ(mqtt::get_package_length(&protocol, nullptr, &length), SW_ERR);
        EXPECT_ERREQ(SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    }
    swoole_set_last_error(saved_error);
}

TEST(mqtt_protocol, does_not_include_following_packet_in_length) {
    Protocol protocol{};
    const char packets[] = {'\x30', '\x03', 'a', '\0', 'b', '\xc0', '\x00'};
    PacketLength length{packets, sizeof(packets)};
    EXPECT_EQ(mqtt::get_package_length(&protocol, nullptr, &length), 5);
}
