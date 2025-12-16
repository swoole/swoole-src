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
  | Author:   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
 */

#include "php_swoole_cxx.h"
#include "php_swoole_api.h"
#include "php_swoole_coroutine.h"

#include "swoole_thread.h"

#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <array>

using swoole::Coroutine;
using swoole::PHPContext;
using swoole::PHPCoroutine;

BEGIN_EXTERN_C()
#include "zend_builtin_functions.h"
#include "zend_observer.h"
#include "ext/standard/php_math.h"
#include "ext/json/php_json.h"
END_EXTERN_C()

struct Prof {
    std::string fname;
    std::string file_pos;
    long began_at;
    long cid;
};

struct ProfContext {
    std::array<Prof, 128> profs;
    uint8_t call_stack_level;
};

struct AllocPoint {
    size_t size;
    size_t count;
    std::string at;
};

struct AllocStat {
    size_t total_bytes;
    size_t count;
};

struct BlockingDetectionSpan {
    zend_long began_at;
    size_t switch_count;
    PHPContext::SwapCallback swap_callback;
};

static SW_THREAD_LOCAL struct {
    std::unordered_map<void *, AllocPoint> points;
    std::unordered_set<void *> debug_points;
    std::unordered_map<std::string, zval> backtraces;
    std::unordered_map<std::string, uint32_t> counters;
    size_t loop;
    zend_long threshold;
    bool profiling;
    std::unordered_map<long, ProfContext> co_prof;
    ProfContext main_co_prof;
    std::string prof_root_path;
    zval prof_events;
    size_t fcall_count;
    size_t return_count;
    pid_t pid;
} TracerG;

#define DEBUG 0
#define DEBUG_LINE 16

constexpr int blocking_detection_func_reserve_index = 4;

#if PHP_VERSION_ID < 80400
#define MM_LINE_DC
#define MM_LINE_ORIG_DC
#define MM_LINE_CC
#define MM_LINE_ORIG_RELAY_CC
#else
#define MM_LINE_DC ZEND_FILE_LINE_DC
#define MM_LINE_ORIG_DC ZEND_FILE_LINE_ORIG_DC
#define MM_LINE_CC ZEND_FILE_LINE_RELAY_CC
#define MM_LINE_ORIG_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC
#endif

static void *(*ori_malloc)(size_t MM_LINE_DC MM_LINE_ORIG_DC);
static void (*ori_free)(void *MM_LINE_DC MM_LINE_ORIG_DC);
static void *(*ori_realloc)(void *, size_t MM_LINE_DC MM_LINE_ORIG_DC);

static void *tracer_malloc(size_t size MM_LINE_DC MM_LINE_ORIG_DC);
static void tracer_free(void *ptr MM_LINE_DC MM_LINE_ORIG_DC);
static void *tracer_realloc(void *ptr, size_t size MM_LINE_DC MM_LINE_ORIG_DC);

static void hook_emalloc();
static void unhook_emalloc();

static long tracer_get_time_us() {
    return swoole::time<std::chrono::microseconds>(true);
}

static std::string zstr_to_std_string(zend_string *zs) {
    return std::string(ZSTR_VAL(zs), ZSTR_LEN(zs));
}

static bool str_starts_with(const std::string &str, const std::string &prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

static bool str_ends_with(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static void debug(const char *label, void *ptr, size_t size, uint32_t lineno) {
#if DEBUG
    auto iter = TrackerG.points.find(ptr);
    if (iter != TrackerG.points.end() && str_ends_with(iter->second.at, ":" + std::to_string(lineno))) {
        printf("[%s]\tptr=%p, size=%lu, count=%lu, lineno=%u, at=%s\n",
               label,
               ptr,
               size,
               iter->second.count,
               lineno,
               iter->second.at.c_str());
        if (strcmp(label, "update")) {
            TrackerG.debug_points.insert(ptr);
        }
    }

    if (strcmp(label, "free") && TrackerG.debug_points.find(ptr) != TrackerG.debug_points.end()) {
        TrackerG.debug_points.erase(ptr);
        printf("free ptr=%p\n", ptr);
    }
#endif
}

static uint32_t tracer_get_executed_lineno(void) {
    zend_execute_data *ex = EG(current_execute_data);
    while (ex && (!ex->func || !ZEND_USER_CODE(ex->func->type))) {
        ex = ex->prev_execute_data;
    }

    if (ex && ex->opline) {
        if (EG(exception) && ex->opline->opcode == ZEND_HANDLE_EXCEPTION && ex->opline->lineno == 0 &&
            EG(opline_before_exception)) {
            return EG(opline_before_exception)->lineno;
        }
        return ex->opline->lineno;
    } else {
        return 0;
    }
}

static zend_string *tracer_get_file_and_line() {
    const char *file = zend_get_executed_filename();
    uint32_t lineno = tracer_get_executed_lineno();
    char file_line_buf[1024];
    if (lineno == 0 && strcmp(file, "[no active file]") == 0) {
        return nullptr;
    }
    size_t file_len = strlen(file);
    if (UNEXPECTED(file_len + 100 > sizeof(file_line_buf))) {
        char *tmp_buf = (char *) malloc(file_len + 100);
        if (!tmp_buf) {
            php_printf("tracker out of memory\n");
            zend_bailout();
        }
        sprintf(tmp_buf, "%s:%u", file, lineno);
        zend_string *ret = zend_string_init(tmp_buf, strlen(tmp_buf), 1);
        free(tmp_buf);
        return ret;
    } else {
        sprintf(file_line_buf, "%s:%u", file, lineno);
        return zend_string_init(file_line_buf, strlen(file_line_buf), 1);
    }
}

static zend_string *tracer_get_backtrace() {
    zval backtrace;
    zend_fetch_debug_backtrace(&backtrace, 0, 0, 0);
    auto backtrace_str = zend_trace_to_string(Z_ARRVAL(backtrace), false);
    zval_ptr_dtor(&backtrace);
    return backtrace_str;
}

static long tracer_get_pid() {
    return swoole_thread_get_native_id();
}

static long tracer_get_tid() {
    return swoole_coroutine_get_id();
}

static ProfContext &tracer_get_ctx(long tid) {
    if (tid == TracerG.pid) {
        return TracerG.main_co_prof;
    } else {
        if (TracerG.co_prof.find(tid) == TracerG.co_prof.end()) {
            TracerG.co_prof[tid] = {};
        }
        return TracerG.co_prof[tid];
    }
}

static zend_string *tracer_format_number(long num) {
#if PHP_VERSION_ID >= 80300
    return _php_math_number_format_long(num, 0, ".", 1, ",", 1);
#else
    return _php_math_number_format((double) num, 0, '.', ',');
#endif
}

static std::string format_bytes(uint64_t size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    int unitIndex = 0;
    double adjustedSize = static_cast<double>(size);

    while (adjustedSize >= 1024.0 && unitIndex < 8) {
        adjustedSize /= 1024.0;
        unitIndex++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << adjustedSize << " " << units[unitIndex];
    return oss.str();
}

static void tracer_leak_clear_stat(const std::string &at) {
    for (auto iter = TracerG.points.begin(); iter != TracerG.points.end(); iter++) {
        if (iter->second.at == at) {
            iter = TracerG.points.erase(iter);
            if (iter == TracerG.points.end()) {
                break;
            }
        }
    }
}

static void save_backtrace(const std::string &alloc_at) {
    if (TracerG.backtraces.find(alloc_at) == TracerG.backtraces.end()) {
        zval bt;
        zend_fetch_debug_backtrace(&bt, 0, DEBUG_BACKTRACE_IGNORE_ARGS, 0);
        TracerG.backtraces[alloc_at] = bt;
    }
}

static void add_point(void *ptr, size_t size, zend_string *current_file_lineno) {
    std::string alloc_at = zstr_to_std_string(current_file_lineno);
    TracerG.points[ptr] = {
        size,
        1,
        alloc_at,
    };

    auto iter = TracerG.counters.find(alloc_at);
    if (iter == TracerG.counters.end()) {
        TracerG.counters[alloc_at] = 1;
    } else {
        iter->second++;
        if (iter->second >= TracerG.threshold - 1) {
            save_backtrace(alloc_at);
        }
    }

    debug("new", ptr, size, DEBUG_LINE);
}

static void update_point(AllocPoint &point, void *new_ptr, size_t new_size) {
    TracerG.points[new_ptr] = {
        new_size,
        point.count + 1,
        point.at,
    };

    auto counter_iter = TracerG.counters.find(point.at);
    if (counter_iter != TracerG.counters.end()) {
        counter_iter->second++;
        if (counter_iter->second >= TracerG.threshold - 1) {
            save_backtrace(point.at);
        }
    }

    debug("update", new_ptr, new_size, DEBUG_LINE);
}

static void del_point(void *ptr, decltype(TracerG.points)::iterator &iter) {
    debug("free", ptr, 0, DEBUG_LINE);
    const auto &alloc_at = iter->second.at;
    auto counter_iter = TracerG.counters.find(alloc_at);
    if (counter_iter != TracerG.counters.end()) {
        counter_iter->second--;
    }
    TracerG.points.erase(iter);
}

static void *tracer_malloc(size_t size MM_LINE_DC MM_LINE_ORIG_DC) {
    void *ptr;
    if (ori_malloc) {
        ptr = ori_malloc(size MM_LINE_CC MM_LINE_ORIG_RELAY_CC);
    } else {
        zend_mm_heap *heap = zend_mm_get_heap();
        ptr = zend_mm_alloc(heap, size);
    }

    unhook_emalloc();

    zend_string *current_file_lineno = tracer_get_file_and_line();
    if (current_file_lineno) {
        add_point(ptr, size, current_file_lineno);
        zend_string_release(current_file_lineno);
    }

    hook_emalloc();

    return ptr;
}

static void *tracer_realloc(void *ptr, size_t size MM_LINE_DC MM_LINE_ORIG_DC) {
    void *new_ptr;

    if (ori_realloc) {
        new_ptr = ori_realloc(ptr, size MM_LINE_CC MM_LINE_ORIG_RELAY_CC);
    } else {
        zend_mm_heap *heap = zend_mm_get_heap();
        new_ptr = zend_mm_realloc(heap, ptr, size);
    }

    unhook_emalloc();

    zend_string *current_file_lineno = tracer_get_file_and_line();
    if (current_file_lineno) {
        auto iter = TracerG.points.find(ptr);
        if (iter != TracerG.points.end()) {
            update_point(iter->second, new_ptr, size);
            if (new_ptr != ptr) {
                TracerG.points.erase(iter);
            }
        } else {
            add_point(new_ptr, size, current_file_lineno);
        }
        zend_string_release(current_file_lineno);
    }

    hook_emalloc();

    return new_ptr;
}

static void tracer_free(void *ptr MM_LINE_DC MM_LINE_ORIG_DC) {
    if (ori_free) {
        ori_free(ptr MM_LINE_CC MM_LINE_ORIG_RELAY_CC);
    } else {
        zend_mm_heap *heap = zend_mm_get_heap();
        zend_mm_free(heap, ptr);
    }

    auto iter = TracerG.points.find(ptr);
    if (iter != TracerG.points.end()) {
        del_point(ptr, iter);
    }
}

static void hook_emalloc() {
    zend_mm_heap *heap = zend_mm_get_heap();
    zend_mm_get_custom_handlers(heap, &ori_malloc, &ori_free, &ori_realloc);
    zend_mm_set_custom_handlers(heap, &tracer_malloc, &tracer_free, &tracer_realloc);
}

static void unhook_emalloc() {
    zend_mm_heap *heap = zend_mm_get_heap();
    if (ori_malloc || ori_free || ori_realloc) {
        zend_mm_set_custom_handlers(heap, ori_malloc, ori_free, ori_realloc);
        ori_malloc = NULL;
        ori_free = NULL;
        ori_realloc = NULL;
    } else {
        *((int *) heap) = 0;
    }
}

static void profiling_begin(zend_string *root_symbol, zend_execute_data *execute_data) {
    zend_function *fbc = execute_data->func;
    auto type = fbc->type;

    if (!TracerG.profiling || type == ZEND_INTERNAL_FUNCTION) {
        return;
    }

    auto ts = tracer_get_time_us();
    zend_string *fn_name = fbc->common.function_name;
    std::string fn;
    std::string file_pos;

    if (fbc->common.scope) {
        zend_string *class_name = fbc->common.scope->name;
        fn = std::string(ZSTR_VAL(class_name)) + "::" + std::string(ZSTR_VAL(fn_name));
    } else {
        fn = std::string(ZSTR_VAL(fn_name));
    }

#if DEBUG
    printf("fn=%s, level=%d \n", fn.c_str(), TracerG.call_stack_level);
#endif

    zend_string *current_file_lineno = tracer_get_file_and_line();
    if (current_file_lineno) {
        file_pos = zstr_to_std_string(current_file_lineno);
        if (str_starts_with(file_pos, TracerG.prof_root_path)) {
            file_pos =
                file_pos.substr(TracerG.prof_root_path.length(), file_pos.length() - TracerG.prof_root_path.length());
        }
        zend_string_release(current_file_lineno);
    }

    auto tid = tracer_get_tid();

    Prof prof{
        fn,
        file_pos,
        ts,
        tid,
    };

    auto &ctx = tracer_get_ctx(tid);
    ctx.profs[ctx.call_stack_level++] = prof;
}

static void profiling_clear() {
    zval_ptr_dtor(&TracerG.prof_events);
    ZVAL_NULL(&TracerG.prof_events);
    TracerG.main_co_prof = {};
    TracerG.co_prof.clear();
    TracerG.profiling = false;
}

static void profiling_end() {
    auto tid = tracer_get_tid();
    auto &ctx = tracer_get_ctx(tid);

    assert(ctx.call_stack_level > 0);

    ctx.call_stack_level--;

    auto &prof = ctx.profs[ctx.call_stack_level];

#if DEBUG
    printf("return level=%d, count=%zu, func=%p\n",
           TracerG.call_stack_level,
           array_count(&TracerG.prof_events),
           prof.fname.c_str());
#endif

    auto te = tracer_get_time_us();

    zval event;
    array_init(&event);

    std::string name;
    if (prof.file_pos.length() > 0) {
        name = prof.fname + " (" + prof.file_pos + ")";
    } else {
        name = prof.fname;
    }

    add_assoc_stringl_ex(&event, ZEND_STRL("name"), name.c_str(), name.length());
    add_assoc_string_ex(&event, ZEND_STRL("ph"), "X");
    add_assoc_string_ex(&event, ZEND_STRL("cat"), "FEE");
    add_assoc_double_ex(&event, ZEND_STRL("ts"), prof.began_at);
    add_assoc_double_ex(&event, ZEND_STRL("dur"), te - prof.began_at);
    add_assoc_long_ex(&event, ZEND_STRL("pid"), tracer_get_pid());
    add_assoc_long_ex(&event, ZEND_STRL("tid"), tid);

    add_next_index_zval(&TracerG.prof_events, &event);

#if DEBUG
    printf("fn=%s, begun_at=%f, dr=%f, at=%s\n",
           prof.fname.c_str(),
           prof.began_at,
           te - prof.began_at,
           prof.file_pos.c_str());
#endif
}

static void tracer_observer_begin(zend_execute_data *execute_data) {
    if (SWOOLE_G(profile)) {
        if (!TracerG.profiling || execute_data->func->type == ZEND_INTERNAL_FUNCTION) {
            return;
        }
        profiling_begin(NULL, execute_data);
    }

    if (SWOOLE_G(blocking_detection)) {
        auto ctx = (PHPContext *) swoole::Coroutine::get_current_task();
        if (ctx) {
            auto span = new BlockingDetectionSpan;
            span->began_at = tracer_get_time_us();
            span->switch_count = ctx->switch_count = 0;
            span->swap_callback = [](PHPContext *ctx) { ctx->switch_count++; };
            ctx->on_resume = &span->swap_callback;
            ctx->on_yield = &span->swap_callback;
            execute_data->func->internal_function.reserved[blocking_detection_func_reserve_index] = span;
        }
    }
}

static void tracer_observer_end(zend_execute_data *execute_data, zval *return_value) {
    if (SWOOLE_G(profile)) {
        if (!TracerG.profiling || execute_data->func->type == ZEND_INTERNAL_FUNCTION) {
            return;
        }
        profiling_end();
    }

    if (SWOOLE_G(blocking_detection)) {
        PHPContext *ctx = PHPCoroutine::get_context();
        if (!ctx || execute_data->func->type != ZEND_INTERNAL_FUNCTION) {
            return;
        }

        ctx->on_resume = nullptr;
        ctx->on_yield = nullptr;

        auto fn = &execute_data->func->internal_function;
        auto span = (BlockingDetectionSpan *) fn->reserved[blocking_detection_func_reserve_index];
        if (!span) {
            return;
        }
        fn->reserved[blocking_detection_func_reserve_index] = nullptr;

        auto now = tracer_get_time_us();
        auto duration = now - span->began_at;
        if (span->switch_count == ctx->switch_count && duration > SWOOLE_G(blocking_threshold)) {
            auto duration_str = tracer_format_number(duration);
            auto backtrace_str = tracer_get_backtrace();

            const char *scope = nullptr;
            if (execute_data->func->common.scope) {
                scope = ZSTR_VAL(execute_data->func->common.scope->name);
            }

            sw_printf(
                " >>> [Detected blocking I/O in Coroutine#%ld, internal function `%s%s%s()` blocked for %s us]\n%s",
                PHPCoroutine::get_cid(),
                scope ? scope : "",
                scope ? "::" : "",
                fn->function_name->val,
                duration_str->val,
                backtrace_str->val);

            zend_string_release(duration_str);
            zend_string_release(backtrace_str);
        }

        swoole_event_defer(
            [](void *ptr) {
                auto span = (BlockingDetectionSpan *) ptr;
                delete span;
            },
            span);
    }
}

static zend_observer_fcall_handlers tracer_observer(zend_execute_data *execute_data) {
    zend_observer_fcall_handlers empty_handlers = {nullptr, nullptr};

    if (!SWOOLE_G(profile) && !SWOOLE_G(blocking_detection)) {
        return empty_handlers;
    }

    if (!execute_data->func || !execute_data->func->common.function_name) {
        return empty_handlers;
    }

    if (SWOOLE_G(profile) && (!TracerG.profiling || execute_data->func->type != ZEND_USER_FUNCTION)) {
        return empty_handlers;
    }

    if (SWOOLE_G(blocking_detection) && execute_data->func->type != ZEND_INTERNAL_FUNCTION) {
        return empty_handlers;
    }

    return {tracer_observer_begin, tracer_observer_end};
}

PHP_FUNCTION(swoole_tracer_leak_detect) {
    if (!SWOOLE_G(leak_detection)) {
        return;
    }

    zend_long threshold = 64;
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_LONG(threshold)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    std::unordered_map<std::string, AllocStat> stats;
    unhook_emalloc();
    for (auto &point : TracerG.points) {
        auto iter = stats.find(point.second.at);
        if (iter == stats.end()) {
            stats[point.second.at] = {
                point.second.size,
                point.second.count,
            };
        } else {
            iter->second.count += point.second.count;
            iter->second.total_bytes += point.second.size;
        }
    }

    for (auto &stat : stats) {
        if (stat.second.count >= (size_t) threshold) {
            php_printf("[Round#%lu] leak %s bytes, alloc %lu times at %s\n",
                       TracerG.loop,
                       format_bytes(stat.second.total_bytes).c_str(),
                       stat.second.count,
                       stat.first.c_str());

            auto bt_iter = TracerG.backtraces.find(stat.first);
            if (bt_iter != TracerG.backtraces.end()) {
                zend_string *str = zend_trace_to_string(Z_ARR(bt_iter->second), false);
                ZEND_WRITE(ZSTR_VAL(str), ZSTR_LEN(str));
                zend_string_release(str);
            }
            tracer_leak_clear_stat(stat.first);
            php_printf("\n");
        }
    }

    TracerG.threshold = threshold;
    TracerG.loop++;
    hook_emalloc();
}

PHP_FUNCTION(swoole_tracer_prof_begin) {
    if (!SWOOLE_G(profile) || TracerG.profiling) {
        RETURN_FALSE;
    }

    array_init(&TracerG.prof_events);
    TracerG.profiling = true;

    zval *options = NULL; /* optional array arg: for future use */

    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 0, 1)
    Z_PARAM_OPTIONAL
    Z_PARAM_ARRAY(options)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    if (options) {
        zval *pzval = zend_hash_str_find(Z_ARRVAL_P(options), ZEND_STRL("root_path"));
        if (pzval) {
            auto tmp = zval_get_string(pzval);
            TracerG.prof_root_path = zstr_to_std_string(tmp);
            if (TracerG.prof_root_path.at(TracerG.prof_root_path.length() - 1) != '/') {
                TracerG.prof_root_path.append("/");
            }
            zend_string_release(tmp);
        }
    }

    TracerG.pid = getpid();

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_tracer_prof_end) {
    if (!SWOOLE_G(profile) || !TracerG.profiling) {
        RETURN_FALSE;
    }

    zend_string *file;
    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)
    Z_PARAM_STR(file)
    ZEND_PARSE_PARAMETERS_END_EX(RETURN_FALSE);

    zval json;
    array_init(&json);

    zend::array_set(&json, ZEND_STRL("traceEvents"), &TracerG.prof_events);

    zval metadata;
    array_init(&metadata);

    zend::array_set(&metadata, ZEND_STRL("version"), "0.17.1");
    zend::array_set(&metadata, ZEND_STRL("overflow"), false);
    zend::array_set(&json, ZEND_STRL("viztracer_metadata"), &metadata);

    smart_str buf = {};
    if (php_json_encode(&buf, &json, 0) == FAILURE) {
    _fail:
        zval_ptr_dtor(&TracerG.prof_events);
        RETURN_FALSE;
    }

    std::ofstream outputFile(ZSTR_VAL(file), std::ios::binary);
    if (!outputFile.is_open()) {
        goto _fail;
    }

    outputFile.write(buf.s->val, buf.s->len);
    outputFile.close();

    zval_ptr_dtor(&metadata);
    zval_ptr_dtor(&json);

    smart_str_free(&buf);
    profiling_clear();

    RETURN_TRUE;
}

void php_swoole_tracer_minit(int module_number) {
    if (SWOOLE_G(blocking_detection) || SWOOLE_G(profile)) {
        zend_observer_fcall_register(tracer_observer);
        SWOOLE_G(enable_fiber_mock) = true;
    }
}

void php_swoole_tracer_rinit() {
    if (SWOOLE_G(leak_detection)) {
        hook_emalloc();
    }
}

void php_swoole_tracer_rshutdown() {
    if (SWOOLE_G(leak_detection)) {
        unhook_emalloc();
    }

    for (auto &iter : TracerG.backtraces) {
        zval_ptr_dtor(&iter.second);
    }

    profiling_clear();
}
