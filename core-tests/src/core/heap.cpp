#include "test_core.h"
#include "swoole_heap.h"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>

using namespace swoole;

namespace {
class HeapTest : public testing::TestWithParam<Heap::Type> {};

uint64_t priority_for(Heap::Type type, uint64_t value) {
    return type == Heap::MIN_HEAP ? value : 100 - value;
}
}  // namespace

TEST(heap, print_reports_nodes_retained_until_destruction) {
    int value = 7;
    Heap heap(1, Heap::MIN_HEAP);
    ASSERT_NE(heap.push(42, &value), nullptr);
    testing::internal::CaptureStdout();
    heap.print();
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output.find("#1\tpriority=42, data="), 0u);
    EXPECT_EQ(std::count(output.begin(), output.end(), '\n'), 1);
    // Leave the node in the heap: its destructor must release the node, while value remains
    // externally owned. The sanitizer run also checks this cleanup for leaks and invalid frees.
}

TEST_P(HeapTest, growth_preserves_priority_order) {
    Heap heap(0, GetParam());
    EXPECT_EQ(heap.peek(), nullptr);
    EXPECT_EQ(heap.top(), nullptr);
    EXPECT_EQ(heap.pop(), nullptr);
    const std::vector<uint64_t> priorities = {
        0,
        42,
        std::numeric_limits<uint64_t>::max(),
        42,
        1,
        17,
        3,
        100,
        8,
        99,
    };
    std::vector<size_t> values(priorities.size());
    std::multiset<uint64_t> expected;
    for (size_t i = 0; i < priorities.size(); i++) {
        values[i] = i;
        ASSERT_NE(heap.push(priorities[i], &values[i]), nullptr);
        expected.insert(priorities[i]);
        ASSERT_EQ(heap.count(), i + 1);
    }
    while (!expected.empty()) {
        auto best = GetParam() == Heap::MIN_HEAP ? expected.begin() : std::prev(expected.end());
        ASSERT_NE(heap.top(), nullptr);
        EXPECT_EQ(heap.top()->priority, *best);
        auto *value = static_cast<size_t *>(heap.pop());
        ASSERT_NE(value, nullptr);
        ASSERT_LT(*value, priorities.size());
        EXPECT_EQ(priorities[*value], *best);
        expected.erase(best);
        EXPECT_EQ(heap.count(), expected.size());
    }
    EXPECT_EQ(heap.peek(), nullptr);
    EXPECT_EQ(heap.top(), nullptr);
    EXPECT_EQ(heap.pop(), nullptr);
}

TEST_P(HeapTest, priority_changes_move_nodes_in_both_directions) {
    Heap heap(2, GetParam());
    std::array<int, 5> values{{0, 1, 2, 3, 4}};
    std::array<HeapNode *, 5> nodes{};
    for (size_t i = 0; i < values.size(); i++) {
        nodes[i] = heap.push(priority_for(GetParam(), 10 + i * 10), &values[i]);
        ASSERT_NE(nodes[i], nullptr);
    }
    heap.change_priority(priority_for(GetParam(), 0), nodes[4]);
    EXPECT_EQ(heap.peek(), &values[4]);
    heap.change_priority(priority_for(GetParam(), 90), nodes[4]);
    EXPECT_EQ(heap.peek(), &values[0]);
    heap.change_priority(nodes[0]->priority, nodes[0]);
    EXPECT_EQ(heap.peek(), &values[0]);
    EXPECT_EQ(heap.count(), values.size());
    for (int id : {0, 1, 2, 3, 4}) {
        EXPECT_EQ(heap.pop(), &values[id]);
    }
}

TEST_P(HeapTest, arbitrary_removal_repairs_both_directions) {
    Heap heap(2, GetParam());
    const std::array<uint64_t, 7> priorities{{1, 8, 2, 9, 10, 3, 4}};
    std::array<size_t, 7> values{};
    std::array<HeapNode *, 7> nodes{};
    std::map<uint64_t, size_t> expected;
    for (size_t i = 0; i < values.size(); i++) {
        values[i] = i;
        const auto priority = priority_for(GetParam(), priorities[i]);
        nodes[i] = heap.push(priority, &values[i]);
        ASSERT_NE(nodes[i], nullptr);
        expected.emplace(priority, i);
    }
    // Replacing the node with priority 9 by the last node (priority 4) requires bubbling
    // upwards past priority 8. Removing the root afterwards exercises downward repair.
    for (size_t id : {3u, 0u, 6u, 2u, 1u, 4u, 5u}) {
        SCOPED_TRACE(id);
        heap.remove(nodes[id]);
        expected.erase(priority_for(GetParam(), priorities[id]));
        ASSERT_EQ(heap.count(), expected.size());
        if (expected.empty()) {
            EXPECT_EQ(heap.top(), nullptr);
            EXPECT_EQ(heap.peek(), nullptr);
        } else {
            const auto best = GetParam() == Heap::MIN_HEAP ? expected.begin() : std::prev(expected.end());
            ASSERT_NE(heap.top(), nullptr);
            EXPECT_EQ(heap.top()->priority, best->first);
            EXPECT_EQ(heap.peek(), &values[best->second]);
        }
    }
    EXPECT_EQ(heap.pop(), nullptr);
    ASSERT_NE(heap.push(1, &values[0]), nullptr);
    EXPECT_EQ(heap.pop(), &values[0]);
}

INSTANTIATE_TEST_SUITE_P(HeapTypes,
                         HeapTest,
                         testing::Values(Heap::MIN_HEAP, Heap::MAX_HEAP),
                         [](const testing::TestParamInfo<Heap::Type> &info) {
                             return info.param == Heap::MIN_HEAP ? "Min" : "Max";
                         });
