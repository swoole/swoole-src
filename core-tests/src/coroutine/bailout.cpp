#include "test_coroutine.h"
#include "swoole_reactor.h"

using namespace swoole;

TEST(coroutine_bailout, reject_resume_and_cancel) {
    ASSERT_EQ(swoole_event_init(0), SW_OK);
    Coroutine::activate();

    bool resumed = false;
    bool canceled = false;
    long cid = Coroutine::create([&](void *) {
        Coroutine::CancelFunc cancel = [&](Coroutine *co) {
            canceled = true;
            co->resume();
            return true;
        };
        Coroutine::get_current()->yield(&cancel);
        resumed = true;
    });
    auto *co = Coroutine::get_by_cid(cid);
    ASSERT_NE(co, nullptr);

    sw_reactor()->bailout = true;
    co->resume();
    EXPECT_FALSE(resumed);
    EXPECT_FALSE(co->cancel());
    EXPECT_FALSE(canceled);
    EXPECT_FALSE(co->is_canceled());

    // Only the test resets bailout: release the suspended coroutine and verify its cancel callback
    // was preserved. Native callers must not be told that a suppressed cancellation succeeded.
    sw_reactor()->bailout = false;
    EXPECT_TRUE(co->cancel());
    EXPECT_TRUE(canceled);
    EXPECT_TRUE(resumed);
    if (Coroutine::get_by_cid(cid)) {
        Coroutine::get_by_cid(cid)->resume();
    }
    swoole_event_free();
    Coroutine::deactivate();
}
