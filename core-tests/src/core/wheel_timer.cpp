#include "test_core.h"
#include "swoole_wheel_timer.h"

using namespace swoole;
using namespace std;


TEST(wheel_timer, next) {
    constexpr int size = 5;
    WheelTimer wt(size);

    auto t1 = wt.add([&](WheelTimerNode *){
        ASSERT_EQ(wt.get_round(), 6);
    });
    ASSERT_EQ(t1->index_, size - 1);
    wt.next();

    auto t2 = wt.add([&](WheelTimerNode *){
        ASSERT_EQ(wt.get_round(), 9);
    });
    ASSERT_EQ(t2->index_, 0);
    wt.update(t1);

    for (int i = 0; i < 10; i++) {
        if (i < 4) {
            wt.update(t2);
        }
        wt.next();
    }
}

