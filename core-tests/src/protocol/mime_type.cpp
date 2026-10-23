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
#include "swoole_mime_type.h"

using namespace swoole;

namespace {
class MimeTypeTest : public testing::Test {
  protected:
    void SetUp() override {
        original = mime_type::list();
    }

    void TearDown() override {
        // Restore the registry even after a fatal assertion: other tests and
        // shuffled iterations must see the same built-in mappings.
        const auto current = mime_type::list();
        for (const auto &item : current) {
            if (original.find(item.first) == original.end()) {
                mime_type::del(item.first);
            }
        }
        for (const auto &item : original) {
            const auto found = mime_type::list().find(item.first);
            if (found == mime_type::list().end() || found->second != item.second) {
                mime_type::set(item.first, item.second);
            }
        }
    }

    std::unordered_map<std::string, std::string> original;
};
}  // namespace

TEST_F(MimeTypeTest, get) {
    EXPECT_EQ(mime_type::get("test.html.json"), "application/json");
}

TEST_F(MimeTypeTest, exists) {
    EXPECT_TRUE(mime_type::exists("test.html.json"));
}

TEST_F(MimeTypeTest, set) {
    mime_type::set("swoole_test", "application/swoole-core-test");
    EXPECT_EQ(mime_type::get("test.swoole_test"), "application/swoole-core-test");
}

TEST_F(MimeTypeTest, add) {
    ASSERT_TRUE(mime_type::add("swoole_test2", "application/swoole-core-test2"));
    EXPECT_FALSE(mime_type::add("swoole_test2", "application/replacement"));
    EXPECT_EQ(mime_type::get("test.swoole_test2"), "application/swoole-core-test2");
}

TEST_F(MimeTypeTest, del) {
    ASSERT_TRUE(mime_type::del("json"));
    EXPECT_FALSE(mime_type::exists("test.html.json"));
    EXPECT_FALSE(mime_type::del("json"));
    EXPECT_EQ(mime_type::get("test.json"), "application/octet-stream");
}

TEST_F(MimeTypeTest, filename_suffix_is_case_insensitive) {
    for (const auto *filename : {"report.JSON", "report.JsOn", ".json", "/path.with.dots/report.json"}) {
        EXPECT_TRUE(mime_type::exists(filename)) << filename;
        EXPECT_EQ(mime_type::get(filename), "application/json") << filename;
    }
}

TEST_F(MimeTypeTest, unknown_or_empty_suffix_uses_default_without_registering_it) {
    const auto size = mime_type::list().size();
    for (const auto *filename : {"", "LICENSE", "report.", "report.swoole_unknown_suffix"}) {
        EXPECT_FALSE(mime_type::exists(filename)) << filename;
        EXPECT_EQ(mime_type::get(filename), "application/octet-stream") << filename;
    }
    EXPECT_EQ(mime_type::list().size(), size);
}

TEST_F(MimeTypeTest, list_reflects_add_replace_and_remove) {
    const auto &types = mime_type::list();
    const auto size = types.size();
    ASSERT_TRUE(mime_type::add("swoole_registry_test", "application/first"));
    EXPECT_EQ(types.size(), size + 1);
    EXPECT_EQ(types.at("swoole_registry_test"), "application/first");
    mime_type::set("swoole_registry_test", "application/second");
    EXPECT_EQ(types.size(), size + 1);
    EXPECT_EQ(types.at("swoole_registry_test"), "application/second");
    EXPECT_EQ(mime_type::get("file.SWOOLE_REGISTRY_TEST"), "application/second");
    ASSERT_TRUE(mime_type::del("swoole_registry_test"));
    EXPECT_EQ(types.size(), size);
    EXPECT_EQ(types.count("swoole_registry_test"), 0u);
}

TEST_F(MimeTypeTest, replacing_builtin_mapping_does_not_add_an_entry) {
    const auto size = mime_type::list().size();
    mime_type::set("json", "application/custom-json");
    EXPECT_EQ(mime_type::get("file.json"), "application/custom-json");
    EXPECT_EQ(mime_type::list().size(), size);
    EXPECT_FALSE(mime_type::add("json", "application/ignored"));
    EXPECT_EQ(mime_type::get("file.json"), "application/custom-json");
}
