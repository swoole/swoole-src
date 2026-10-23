#include "test_core.h"
#include "swoole_lru_cache.h"

using namespace swoole;
using namespace std;

namespace {
class TrackedCacheValue {
  public:
    explicit TrackedCacheValue(int &destroyed) : destroyed_(destroyed) {}
    ~TrackedCacheValue() {
        destroyed_++;
    }

  private:
    int &destroyed_;
};
}  // namespace

TEST(lru_cache, basic) {
    LRUCache<string> cache(2);
    shared_ptr<string> val = make_shared<string>("hello");
    shared_ptr<string> val1 = make_shared<string>("hello1");

    cache.set("test", val);
    ASSERT_EQ(cache.get("test").get(), val.get());

    cache.set("test", val1);
    ASSERT_EQ(cache.get("test").get(), val1.get());

    cache.del("test");
    ASSERT_EQ(cache.get("test"), nullptr);

    cache.set("test", val);
    ASSERT_EQ(cache.get("test").get(), val.get());

    cache.clear();
    ASSERT_EQ(cache.get("test"), nullptr);
}

TEST(lru_cache, memory_free) {
    int destroyed = 0;
    LRUCache<TrackedCacheValue> cache(2);
    shared_ptr<TrackedCacheValue> val = make_shared<TrackedCacheValue>(destroyed);
    cache.set("test", val);
    ASSERT_EQ(cache.get("test").get(), val.get());
    val.reset();
    ASSERT_EQ(destroyed, 0);
    cache.clear();
    ASSERT_EQ(destroyed, 1);
}

TEST(lru_cache, lru_kick) {
    int destroyed = 0;
    LRUCache<TrackedCacheValue> cache(2);
    shared_ptr<TrackedCacheValue> val = make_shared<TrackedCacheValue>(destroyed);
    shared_ptr<TrackedCacheValue> val1 = make_shared<TrackedCacheValue>(destroyed);
    shared_ptr<TrackedCacheValue> val2 = make_shared<TrackedCacheValue>(destroyed);
    shared_ptr<TrackedCacheValue> val3 = make_shared<TrackedCacheValue>(destroyed);

    cache.set("test", val);
    ASSERT_EQ(cache.get("test").get(), val.get());
    val.reset();
    ASSERT_EQ(destroyed, 0);

    cache.set("test1", val1);
    ASSERT_EQ(cache.get("test1").get(), val1.get());
    val1.reset();
    ASSERT_EQ(destroyed, 0);

    cache.set("test2", val2);
    ASSERT_EQ(cache.get("test2").get(), val2.get());
    val2.reset();
    ASSERT_EQ(destroyed, 1);
    ASSERT_EQ(cache.get("test"), nullptr);

    shared_ptr<TrackedCacheValue> val4 = make_shared<TrackedCacheValue>(destroyed);
    cache.set("test1", val4);  // Replacing an existing key releases its old value without evicting another key.
    ASSERT_EQ(cache.get("test1").get(), val4.get());
    ASSERT_EQ(destroyed, 2);

    cache.set("test3", val3);
    ASSERT_EQ(cache.get("test3").get(), val3.get());
    val3.reset();
    ASSERT_EQ(destroyed, 3);
    ASSERT_EQ(cache.get("test2"), nullptr);

    cache.clear();
    ASSERT_EQ(destroyed, 4);
}

TEST(lru_cache, reads_and_replacements_refresh_eviction_order) {
    LRUCache<string> cache(2);
    const auto first = make_shared<string>("first");
    const auto second = make_shared<string>("second");
    const auto third = make_shared<string>("third");
    const auto replacement = make_shared<string>("replacement");
    cache.set("first", first);
    cache.set("second", second);
    ASSERT_EQ(cache.get("first"), first);
    cache.set("third", third);
    EXPECT_EQ(cache.get("second"), nullptr);
    EXPECT_EQ(cache.get("first"), first);
    EXPECT_EQ(cache.get("third"), third);
    cache.set("first", replacement);
    cache.set("fourth", second);
    EXPECT_EQ(cache.get("third"), nullptr);
    EXPECT_EQ(cache.get("first"), replacement);
    EXPECT_EQ(cache.get("fourth"), second);
    cache.del("missing");
    EXPECT_EQ(cache.get("first"), replacement);
}

TEST(lru_cache, single_entry_cache_can_be_reused_after_delete_and_clear) {
    LRUCache<string> cache(1);
    const auto value = make_shared<string>("value");
    cache.set("first", value);
    cache.set("second", value);
    EXPECT_EQ(cache.get("first"), nullptr);
    EXPECT_EQ(cache.get("second"), value);
    cache.del("second");
    EXPECT_EQ(cache.get("second"), nullptr);
    cache.clear();
    cache.clear();
    cache.set("third", value);
    EXPECT_EQ(cache.get("third"), value);
}
