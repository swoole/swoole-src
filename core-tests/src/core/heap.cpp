#include "test_core.h"
#include "swoole_heap.h"
#include "swoole_util.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <type_traits>

using namespace swoole;

static_assert(!std::is_copy_constructible<Heap>::value, "Heap owns its nodes and must not be copied");
static_assert(!std::is_copy_assignable<Heap>::value, "Heap owns its nodes and must not be copy-assigned");

namespace {
class HeapTest : public testing::TestWithParam<Heap::Type> {};

uint64_t priority_for(Heap::Type type, uint64_t value) {
    return type == Heap::MIN_HEAP ? value : 100 - value;
}

// Tracks the single HeapNode* array allocation inside a death-test child. A successful
// realloc must be published with nodes.release(); otherwise the old owner is either freed
// twice (moving realloc) or freed while still live (in-place realloc).
struct ArrayAllocatorState {
    void *array = nullptr;
    size_t array_bytes = 0;
    int malloc_calls = 0;
    int realloc_calls = 0;
    int free_calls = 0;
    void *freed = nullptr;
    bool wrong_pointer = false;
    bool freed_twice = false;
};

ArrayAllocatorState array_allocator_state;

void *array_allocator_malloc(size_t bytes) {
    void *p = std::malloc(bytes);
    if (p) {
        array_allocator_state.array = p;
        array_allocator_state.array_bytes = bytes;
        array_allocator_state.malloc_calls++;
    }
    return p;
}

void *array_allocator_calloc(size_t nmemb, size_t bytes) {
    return std::calloc(nmemb, bytes);
}

void *array_allocator_realloc(void *old, size_t bytes) {
    // Always move, so a missing nodes.release() would free an already-released block.
    void *p = std::malloc(bytes);
    if (!p) {
        return nullptr;
    }
    if (old) {
        const size_t slots = std::min(array_allocator_state.array_bytes, bytes) / sizeof(HeapNode *);
        std::copy_n(static_cast<HeapNode **>(old), slots, static_cast<HeapNode **>(p));
        std::free(old);
    }
    array_allocator_state.array = p;
    array_allocator_state.array_bytes = bytes;
    array_allocator_state.realloc_calls++;
    return p;
}

void array_allocator_free(void *ptr) {
    if (array_allocator_state.freed != nullptr) {
        array_allocator_state.freed_twice = true;
    }
    if (ptr != array_allocator_state.array) {
        array_allocator_state.wrong_pointer = true;
    }
    array_allocator_state.freed = ptr;
    array_allocator_state.free_calls++;
    std::free(ptr);
}

// Kept out of EXPECT_EXIT's macro argument: braced initialisers and template arguments
// contain commas that the preprocessor would treat as extra macro arguments.
int run_moving_growth_child() {
    const Allocator saved = SwooleG.std_allocator;
    SwooleG.std_allocator.malloc = array_allocator_malloc;
    SwooleG.std_allocator.calloc = array_allocator_calloc;
    SwooleG.std_allocator.realloc = array_allocator_realloc;
    SwooleG.std_allocator.free = array_allocator_free;

    bool ok = true;
    {
        Heap heap(1, Heap::MIN_HEAP);
        std::array<int, 40> values{};
        std::array<HeapNode *, 40> handles{};
        for (size_t i = 0; i < values.size(); i++) {
            values[i] = static_cast<int>(i);
            handles[i] = heap.push(static_cast<uint64_t>(i), &values[i]);
            if (!handles[i]) {
                ok = false;
            }
        }
        // growth() reallocates the index array several times; the separately owned
        // nodes must remain reachable through the original handles afterwards.
        for (size_t i = 0; i < handles.size(); i++) {
            if (!handles[i] || handles[i]->data != &values[i] ||
                handles[i]->priority != static_cast<uint64_t>(i) || handles[i]->position < 1 ||
                handles[i]->position > heap.count()) {
                ok = false;
            }
        }
        if (heap.count() != values.size() || heap.peek() != &values[0]) {
            ok = false;
        }
    }  // ~Heap: releases every node and frees the index array exactly once
    SwooleG.std_allocator = saved;

    if (array_allocator_state.malloc_calls != 1 || array_allocator_state.realloc_calls == 0 ||
        array_allocator_state.free_calls != 1 || array_allocator_state.freed_twice ||
        array_allocator_state.wrong_pointer || array_allocator_state.freed != array_allocator_state.array) {
        ok = false;
    }
    return ok ? 0 : 1;
}
}  // namespace

TEST(heap, impossible_capacities_are_rejected_before_allocating) {
    const size_t max_slots =
        std::min<size_t>(std::numeric_limits<uint32_t>::max(), std::numeric_limits<size_t>::max() / sizeof(HeapNode *));
    for (const size_t capacity : {max_slots, max_slots + 1, std::numeric_limits<size_t>::max()}) {
        EXPECT_EXIT(
            {
                // An invalid capacity must fail without attempting a huge or wrapped allocation.
                SwooleG.std_allocator.malloc = [](size_t) -> void * { _exit(2); };
                try {
                    Heap heap(capacity, Heap::MIN_HEAP);
                } catch (const std::length_error &) {
                    _exit(0);
                }
                _exit(1);
            },
            testing::ExitedWithCode(0),
            "");
    }
}

TEST(heap, largest_representable_capacity_is_not_truncated) {
    const size_t max_slots =
        std::min<size_t>(std::numeric_limits<uint32_t>::max(), std::numeric_limits<size_t>::max() / sizeof(HeapNode *));
    EXPECT_EXIT(
        {
            SwooleG.std_allocator.malloc = [](size_t bytes) -> void * {
                const size_t slots = std::min<size_t>(std::numeric_limits<uint32_t>::max(),
                                                      std::numeric_limits<size_t>::max() / sizeof(HeapNode *));
                _exit(bytes == slots * sizeof(HeapNode *) ? 0 : 2);
            };
            Heap heap(max_slots - 1, Heap::MAX_HEAP);
            _exit(1);
        },
        testing::ExitedWithCode(0),
        "");
}

TEST(heap, constructor_throws_bad_alloc_on_allocation_failure) {
    EXPECT_EXIT(
        {
            SwooleG.std_allocator.malloc = [](size_t) -> void * { return nullptr; };
            try {
                Heap heap(8, Heap::MIN_HEAP);
            } catch (const std::bad_alloc &) {
                _exit(0);
            }
            _exit(1);
        },
        testing::ExitedWithCode(0),
        "");
}

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

TEST_P(HeapTest, failed_growth_preserves_handles_and_allows_retry) {
    Heap heap(1, GetParam());
    std::array<int, 2> values{{0, 1}};
    auto *first = heap.push(priority_for(GetParam(), 10), &values[0]);
    ASSERT_NE(first, nullptr);

    const auto previous_realloc = SwooleG.std_allocator.realloc;
    ON_SCOPE_EXIT {
        SwooleG.std_allocator.realloc = previous_realloc;
    };
    SwooleG.std_allocator.realloc = [](void *, size_t) -> void * {
        errno = ENOMEM;
        return nullptr;
    };
    EXPECT_EQ(heap.push(priority_for(GetParam(), 0), &values[1]), nullptr);
    EXPECT_EQ(heap.count(), 1u);
    EXPECT_EQ(heap.top(), first);
    EXPECT_EQ(heap.peek(), &values[0]);
    EXPECT_EQ(first->priority, priority_for(GetParam(), 10));
    EXPECT_EQ(first->position, 1u);

    SwooleG.std_allocator.realloc = previous_realloc;
    ASSERT_NE(heap.push(priority_for(GetParam(), 0), &values[1]), nullptr);
    EXPECT_EQ(heap.pop(), &values[1]);
    EXPECT_EQ(heap.pop(), &values[0]);
    EXPECT_EQ(heap.count(), 0u);
    EXPECT_EQ(heap.pop(), nullptr);
}

TEST(heap, moving_growth_keeps_array_owned_once_and_handles_stable) {
    EXPECT_EXIT({ _exit(run_moving_growth_child()); }, testing::ExitedWithCode(0), "");
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

TEST_P(HeapTest, data_stays_caller_owned_across_single_element_edges) {
    int value = 1234;
    auto *owned = new int(5678);
    {
        Heap heap(1, GetParam());
        EXPECT_EQ(heap.pop(), nullptr);
        EXPECT_EQ(heap.peek(), nullptr);
        EXPECT_EQ(heap.top(), nullptr);

        auto *only = heap.push(priority_for(GetParam(), 1), owned);
        ASSERT_NE(only, nullptr);
        EXPECT_EQ(heap.count(), 1u);
        EXPECT_EQ(heap.top(), only);
        EXPECT_EQ(heap.peek(), owned);

        // Removing the last-position node (pos == last) must empty the heap cleanly.
        heap.remove(only);
        EXPECT_EQ(heap.count(), 0u);
        EXPECT_EQ(heap.top(), nullptr);
        EXPECT_EQ(heap.pop(), nullptr);

        // A fresh push and pop on a single element exercises pop()'s remove() path.
        auto *again = heap.push(priority_for(GetParam(), 2), &value);
        ASSERT_NE(again, nullptr);
        EXPECT_EQ(heap.pop(), &value);
        EXPECT_EQ(heap.count(), 0u);
    }
    // HeapNode::data is caller-owned: destroying the heap must not touch it.
    EXPECT_EQ(*owned, 5678);
    EXPECT_EQ(value, 1234);
    delete owned;
}

TEST_P(HeapTest, mixed_operations_match_a_reference_queue_and_preserve_positions) {
    Heap heap(0, GetParam());
    std::array<size_t, 128> values{};
    std::array<HeapNode *, 128> nodes{};
    std::multiset<uint64_t> expected;
    std::mt19937 random(0x53574f4f);
    for (size_t i = 0; i < values.size(); i++) {
        values[i] = i;
        const uint64_t priority = random() % 64;
        nodes[i] = heap.push(priority, &values[i]);
        ASSERT_NE(nodes[i], nullptr);
        expected.insert(priority);
    }
    for (size_t step = 0; step < 2000; step++) {
        SCOPED_TRACE(step);
        const size_t index = random() % nodes.size();
        const uint64_t priority = step % 17 == 0 ? std::numeric_limits<uint64_t>::max() : random() % 64;
        switch (random() % 4) {
        case 0:
            if (!nodes[index]) {
                nodes[index] = heap.push(priority, &values[index]);
                ASSERT_NE(nodes[index], nullptr);
                expected.insert(priority);
            }
            break;
        case 1:
            if (nodes[index]) {
                const auto old = expected.find(nodes[index]->priority);
                ASSERT_NE(old, expected.end());
                expected.erase(old);
                heap.change_priority(priority, nodes[index]);
                expected.insert(priority);
            }
            break;
        case 2:
            if (nodes[index]) {
                const auto old = expected.find(nodes[index]->priority);
                ASSERT_NE(old, expected.end());
                expected.erase(old);
                heap.remove(nodes[index]);
                nodes[index] = nullptr;
            }
            break;
        case 3:
            if (!expected.empty()) {
                const auto best = GetParam() == Heap::MIN_HEAP ? expected.begin() : std::prev(expected.end());
                ASSERT_NE(heap.top(), nullptr);
                ASSERT_EQ(heap.top()->priority, *best);
                const size_t removed_index = *static_cast<size_t *>(heap.peek());
                ASSERT_LT(removed_index, nodes.size());
                EXPECT_EQ(heap.pop(), &values[removed_index]);
                nodes[removed_index] = nullptr;
                expected.erase(best);
            }
            break;
        }

        ASSERT_EQ(heap.count(), expected.size());
        std::array<bool, 129> positions{};
        size_t live = 0;
        for (size_t i = 0; i < nodes.size(); i++) {
            if (nodes[i]) {
                live++;
                EXPECT_EQ(nodes[i]->data, &values[i]);
                ASSERT_GE(nodes[i]->position, 1u);
                ASSERT_LE(nodes[i]->position, heap.count());
                ASSERT_FALSE(positions[nodes[i]->position]);
                positions[nodes[i]->position] = true;
            }
        }
        EXPECT_EQ(live, expected.size());
        if (expected.empty()) {
            EXPECT_EQ(heap.top(), nullptr);
            EXPECT_EQ(heap.peek(), nullptr);
        } else {
            const auto best = GetParam() == Heap::MIN_HEAP ? expected.begin() : std::prev(expected.end());
            ASSERT_NE(heap.top(), nullptr);
            EXPECT_EQ(heap.top()->priority, *best);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(HeapTypes,
                         HeapTest,
                         testing::Values(Heap::MIN_HEAP, Heap::MAX_HEAP),
                         [](const testing::TestParamInfo<Heap::Type> &info) {
                             return info.param == Heap::MIN_HEAP ? "Min" : "Max";
                         });
