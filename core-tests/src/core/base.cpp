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
#include "swoole_server.h"
#include "swoole_file.h"
#include "swoole_util.h"
#include "swoole.h"
#include "swoole_config.h"

#include <sys/resource.h>

using namespace swoole;
using namespace std;

static const string test_data("hello world\n");

TEST(base, datahead_dump) {
    swDataHead data = {};
    data.fd = 123;
    char buf[128];
    size_t n = data.dump(buf, sizeof(buf));
    data.print();

    ASSERT_GT(std::string(buf, n).find("int fd = 123;"), 1);
}

TEST(base, dec2hex) {
    auto result = swoole_dec2hex(2684326179, 16);
    ASSERT_STREQ(result, "9fff9123");
    sw_free(result);
}

TEST(base, hex2dec) {
    size_t n_parsed;
    ASSERT_EQ(swoole_hex2dec("9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 8);
    ASSERT_EQ(swoole_hex2dec("0x9fff9123", &n_parsed), 2684326179);
    ASSERT_EQ(n_parsed, 10);
    ASSERT_EQ(swoole_hex2dec("f", &n_parsed), 15);
    ASSERT_EQ(n_parsed, 1);
}

TEST(base, random_string) {
    char buf[1024] = {};
    swoole_random_string(buf, sizeof(buf) - 1);
    ASSERT_EQ(strlen(buf), sizeof(buf) - 1);
}

static size_t test_sw_vsnprintf(char *buf, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t result = sw_vsnprintf(buf, size, format, args);
    va_end(args);
    return result;
}

TEST(base, file_put_contents) {
    char buf[65536];
    swoole_random_string(buf, sizeof(buf) - 1);
    ASSERT_TRUE(file_put_contents(TEST_TMP_FILE, buf, sizeof(buf)));
    auto result = file_get_contents(TEST_TMP_FILE);
    ASSERT_STREQ(buf, result->value());
}

TEST(base, file_get_size) {
    File f(TEST_TMP_FILE, File::WRITE | File::CREATE);
    char buf[65536];
    swoole_random_string(buf, sizeof(buf) - 1);

    ASSERT_TRUE(f.ready());
    f.truncate(0);
    f.set_offset(0);
    f.write(buf, sizeof(buf) - 1);
    f.close();

    ASSERT_EQ(file_get_size(TEST_TMP_FILE), sizeof(buf) - 1);
}

TEST(base, version_compare) {
    ASSERT_EQ(swoole_version_compare("1.2.1", "1.2.0"), 1);
    ASSERT_EQ(swoole_version_compare("1.2.3", "1.3.0"), -1);
    ASSERT_EQ(swoole_version_compare("1.2.3", "1.2.9"), -1);
    ASSERT_EQ(swoole_version_compare("1.2.0", "1.2.0"), 0);
}

TEST(base, common_divisor) {
    ASSERT_EQ(swoole_common_divisor(16, 12), 4);
    ASSERT_EQ(swoole_common_divisor(6, 15), 3);
    ASSERT_EQ(swoole_common_divisor(32, 16), 16);
}

TEST(base, common_multiple) {
    ASSERT_EQ(swoole_common_multiple(16, 12), 48);
    ASSERT_EQ(swoole_common_multiple(6, 15), 30);
    ASSERT_EQ(swoole_common_multiple(32, 16), 32);
}

TEST(base, shell_exec) {
    pid_t pid;
    string str = "md5sum " + test::get_jpg_file();
    int _pipe = swoole_shell_exec(str.c_str(), &pid, 0);
    ASSERT_GT(_pipe, 0);
    ASSERT_GT(pid, 0);
    char buf[1024] = {};
    ssize_t n = read(_pipe, buf, sizeof(buf) - 1);
    ASSERT_GT(n, 0);
    ASSERT_STREQ(string(buf).substr(0, sizeof(TEST_JPG_MD5SUM) - 1).c_str(), TEST_JPG_MD5SUM);
    close(_pipe);

    str = "md5sum test.abcdef";
    _pipe = swoole_shell_exec(str.c_str(), &pid, 1);
    memset(buf, 0, sizeof(buf));
    ssize_t length = 0;
    while (1) {
        n = read(_pipe, buf + length, sizeof(buf) - 1 - length);
        length += n;
        if (n > 0) {
            continue;
        }
        break;
    }
    ASSERT_GT(length, 0);

    ASSERT_STREQ(buf, string("md5sum: test.abcdef: No such file or directory\n").c_str());
    close(_pipe);
}

TEST(base, file_size) {
    auto file = test::get_jpg_file();
    ssize_t file_size = file_get_size(file);
    ASSERT_GT(file_size, 0);
    auto fp = fopen(file.c_str(), "r+");
    ASSERT_TRUE(fp);
    ASSERT_EQ(file_get_size(fp), file_size);
    fclose(fp);
}

TEST(base, eventdata_pack) {
    EventData ed1{};

    ASSERT_TRUE(Server::task_pack(&ed1, test_data.c_str(), test_data.length()));
    ASSERT_EQ(string(ed1.data, ed1.info.len), test_data);

    EventData ed2{};
    ASSERT_EQ(swoole_random_bytes(sw_tg_buffer()->str, SW_BUFFER_SIZE_BIG), SW_BUFFER_SIZE_BIG);
    ASSERT_TRUE(Server::task_pack(&ed2, sw_tg_buffer()->str, SW_BUFFER_SIZE_BIG));

    String _buffer(SW_BUFFER_SIZE_BIG);
    PacketPtr packet;
    ASSERT_TRUE(Server::task_unpack(&ed2, &_buffer, &packet));
    ASSERT_EQ(memcmp(sw_tg_buffer()->str, _buffer.str, SW_BUFFER_SIZE_BIG), 0);
}

TEST(base, stack_defer_fn) {
    int count = 0;

    ON_SCOPE_EXIT {
        count++;
        ASSERT_EQ(count, 2);
    };

    ON_SCOPE_EXIT {
        count++;
        ASSERT_EQ(count, 1);
    };
}

TEST(base, string_format) {
    char *data = swoole_string_format(128, "hello %d world, %s is best.", 2020, "swoole");
    ASSERT_STREQ(data, "hello 2020 world, swoole is best.");
    sw_free(data);
}

TEST(base, dirname) {
    ASSERT_EQ(dirname("/hello/world/index.html.abc"), "/hello/world");
    ASSERT_EQ(dirname("/hello/world"), "/hello");
    ASSERT_EQ(dirname("/root"), "/");
    ASSERT_EQ(dirname("/"), "/");
}

TEST(base, mkdir_recursive) {
    String dir(PATH_MAX + 2);
    dir.append_random_bytes(PATH_MAX, true);
    ASSERT_FALSE(swoole_mkdir_recursive(dir.to_std_string()));
}

TEST(base, set_task_tmpdir) {
    auto ori_tmpdir = swoole_get_task_tmpdir();
    ASSERT_FALSE(swoole_set_task_tmpdir("aaa"));

    size_t length = SW_TASK_TMP_PATH_SIZE + 1;
    char too_long_dir[length + 1] = {};
    swoole_random_string(too_long_dir + 1, length - 1);
    too_long_dir[0] = '/';
    ASSERT_FALSE(swoole_set_task_tmpdir(too_long_dir));

    const char *tmpdir = "/tmp/swoole/core_tests/base";
    ASSERT_TRUE(swoole_set_task_tmpdir(tmpdir));
    File fp = make_tmpfile();
    ASSERT_TRUE(fp.ready());

    char buf[128];
    swoole_random_string(buf, sizeof(buf) - 2);
    buf[sizeof(buf) - 2] = '\n';

    fp.write(buf, sizeof(buf) - 1);
    fp.close();

    ASSERT_EQ(swoole::dirname(fp.get_path()), tmpdir);
    ASSERT_STREQ(swoole::file_get_contents(fp.get_path())->str, buf);

    unlink(fp.get_path().c_str());
    rmdir(tmpdir);

    char buf2[264];
    swoole_random_string(buf2, sizeof(buf2) - 1);
    memcpy(buf2, "/tmp/", 5);
    buf2[64] = '/';
    buf2[128] = '/';
    buf2[192] = '/';
    buf2[256] = '/';
    std::string dir(buf2);
    ASSERT_FALSE(swoole_set_task_tmpdir(dir));

    test::recursive_rmdir(dir.c_str());

    ASSERT_TRUE(swoole_set_task_tmpdir(ori_tmpdir));
}

TEST(base, version) {
    ASSERT_STREQ(swoole_version(), SWOOLE_VERSION);
    ASSERT_EQ(swoole_version_id(), SWOOLE_VERSION_ID);
    ASSERT_EQ(swoole_api_version_id(), SWOOLE_API_VERSION_ID);
}

TEST(base, hook) {
    int count = 0;
    swoole_add_hook(
        SW_GLOBAL_HOOK_END,
        [](void *data) -> void {
            int *_count = (int *) data;
            *_count = 9999;
        },
        1);
    ASSERT_TRUE(swoole_isset_hook(SW_GLOBAL_HOOK_END));
    swoole_call_hook(SW_GLOBAL_HOOK_END, &count);
    ASSERT_EQ(count, 9999);
}

TEST(base, intersection) {
    std::vector<std::string> vec1{"index.php", "index.html", "default.html"};

    std::set<std::string> vec2{".", "..", "default.html", "index.php", "test.html", "a.json", "index.php"};
    ASSERT_EQ("index.php", swoole::intersection(vec1, vec2));

    std::set<std::string> vec3{"a", "zh中", "、r\n"};
    ASSERT_EQ("", swoole::intersection(vec1, vec3));
}

TEST(base, itoa) {
    char buf[128];
    long value = 123456987;
    int n = swoole_itoa(buf, value);

    ASSERT_EQ(n, 9);
    ASSERT_STREQ(buf, "123456987");
}

TEST(base, get_systemd_listen_fds) {
    ASSERT_EQ(swoole_get_systemd_listen_fds(), -1);
    setenv("LISTEN_FDS", to_string(SW_MAX_LISTEN_PORT + 1).c_str(), 1);
    ASSERT_EQ(swoole_get_systemd_listen_fds(), -1);
    setenv("LISTEN_FDS", to_string(SW_MAX_LISTEN_PORT - 1).c_str(), 1);
    ASSERT_EQ(swoole_get_systemd_listen_fds(), SW_MAX_LISTEN_PORT - 1);
}

TEST(base, type_size) {
    ASSERT_EQ(swoole_type_size('c'), 1);
    ASSERT_EQ(swoole_type_size('s'), 2);
    ASSERT_EQ(swoole_type_size('l'), 4);
    ASSERT_EQ(swoole_type_size('b'), 0);
    ASSERT_EQ(swoole_type_size('q'), 8);
    ASSERT_EQ(swoole_type_size('P'), 8);
}

size_t swoole_fatal_error_impl(const char *format, ...) {
    size_t retval = 0;
    va_list args;
    va_start(args, format);

    char buf[128];
    retval += sw_vsnprintf(buf, 128, format, args);
    va_end(args);
    return retval;
}

TEST(base, vsnprintf) {
    ASSERT_GT(swoole_fatal_error_impl("Hello %s", "World!!!"), 0);

    char buffer[10];
    {
        // The 9th byte will be set to \ 0, discarding one character
        size_t result = test_sw_vsnprintf(buffer, 9, "Test %d", 1234);
        EXPECT_STREQ(buffer, "Test 123");
        EXPECT_EQ(result, 8);
    }

    {
        size_t result = test_sw_vsnprintf(buffer, sizeof(buffer), "Test %d is too long", 12345);
        EXPECT_EQ(buffer[sizeof(buffer) - 1], '\0');
        EXPECT_EQ(result, sizeof(buffer) - 1);
        EXPECT_STREQ(buffer, "Test 1234");
    }
}

TEST(base, snprintf) {
    char buffer[10];
    {
        // The 9th byte will be set to \ 0, discarding one character
        size_t result = sw_snprintf(buffer, 9, "Test %d", 1234);
        EXPECT_STREQ(buffer, "Test 123");
        EXPECT_EQ(result, 8);
    }

    {
        size_t result = sw_snprintf(buffer, sizeof(buffer), "Test %d is too long", 12345);
        EXPECT_EQ(buffer[sizeof(buffer) - 1], '\0');
        EXPECT_EQ(result, sizeof(buffer) - 1);
        EXPECT_STREQ(buffer, "Test 1234");
    }
}

TEST(base, log_level) {
    int level = sw_logger()->get_level();
    swoole_set_log_level(SW_LOG_TRACE);
    swoole_print_backtrace();
    EXPECT_EQ(SW_LOG_TRACE, sw_logger()->get_level());
    swoole_set_log_level(level);
}

TEST(base, trace_flag) {
    int flags = SwooleG.trace_flags;
    swoole_set_trace_flags(SW_TRACE_CARES);
    EXPECT_EQ(SW_TRACE_CARES, SwooleG.trace_flags);
    swoole_set_trace_flags(flags);
}

TEST(base, only_dump) {
    // just dump something
    std::string data = "hello world";
    swoole_dump_ascii(data.c_str(), data.length());
    swoole_dump_bin(data.c_str(), 'C', data.length());
    swoole_dump_hex(data.c_str(), data.length());
    ASSERT_TRUE(true);
}

TEST(base, redirect_stdout) {
    auto file = TEST_LOG_FILE;
    auto out_1 = "hello world, hello swoole!\n";
    auto out_2 = "write to /dev/null\n";
    auto status = test::spawn_exec_and_wait([&]() {
        swoole_redirect_stdout(file);
        printf("%s\n", out_1);
        fflush(stdout);

        swoole_redirect_stdout("/dev/null");
        printf("%s\n", out_2);
        fflush(stdout);

        swoole_clear_last_error();
        swoole_redirect_stdout("/tmp/not-exists/test.log");
        ASSERT_ERREQ(ENOTDIR);
    });
    ASSERT_EQ(status, 0);

    auto rs = swoole::file_get_contents(file);
    ASSERT_NE(rs, nullptr);
    ASSERT_TRUE(rs->contains(out_1));
    ASSERT_FALSE(rs->contains(out_2));
    unlink(file);
}

TEST(base, fatal_error) {
    const char *msg = "core tests fatal error";
    auto status = test::spawn_exec_and_wait([msg]() {
        swoole_set_log_file(TEST_LOG_FILE);
        swoole_fatal_error(9999, msg);
    });
    ASSERT_EQ(WEXITSTATUS(status), 1);

    auto rs = file_get_contents(TEST_LOG_FILE);
    ASSERT_NE(rs, nullptr);
    ASSERT_TRUE(rs->contains(msg));
    ASSERT_TRUE(rs->contains("(ERROR 9999)"));
    File::remove(TEST_LOG_FILE);
}

TEST(base, spinlock) {
    test::counter_init();
    auto counter = test::counter_ptr();
    int n = 4096;

    auto test_fn = [counter, n]() {
        SW_LOOP_N(n) {
            sw_spinlock((sw_atomic_t *) &counter[0]);
            counter[1]++;
            if (i % 100 == 0) {
                usleep(5);
            }
            sw_spinlock_release((sw_atomic_t *) &counter[0]);
        }
    };

    std::thread t1(test_fn);
    std::thread t2(test_fn);

    t1.join();
    t2.join();

    ASSERT_EQ(counter[1], n * 2);
}

TEST(base, futex) {
    sw_atomic_t value = 1;

    std::thread t1([&value] {
        DEBUG() << "wait 1\n";
        ASSERT_EQ(sw_atomic_futex_wait(&value, -1), SW_OK);  // no wait
        value = 0;

        DEBUG() << "wait 2\n";

        ASSERT_EQ(sw_atomic_futex_wait(&value, 0.05), SW_ERR);  // timed out
        ASSERT_EQ(sw_atomic_futex_wait(&value, 0.5), SW_OK);    // success

        DEBUG() << "wait 3\n";

        value = 0;
        ASSERT_EQ(sw_atomic_futex_wait(&value, -1), SW_OK);  // no timeout
    });

    std::thread t2([&value] {
        usleep(100000);
        DEBUG() << "wakeup 1\n";
        ASSERT_EQ(sw_atomic_futex_wakeup(&value, 1), 1);

        DEBUG() << "wakeup 2\n";
        usleep(100000);
        ASSERT_EQ(sw_atomic_futex_wakeup(&value, 1), 1);
    });

    t1.join();
    t2.join();
}

static int test_fork_fail(const std::function<void(void)> &after_fork_fail = nullptr) {
    rlimit rl{};
    rlim_t ori_nproc_max;
    int count = 0;
    rlim_t nproc_max = 32;

    // 获取当前 NPROC 限制
    if (getrlimit(RLIMIT_NPROC, &rl) != 0) {
        perror("getrlimit failed");
        return 1;
    }

    printf("Current NPROC limit: soft=%lu, hard=%lu\n", rl.rlim_cur, rl.rlim_max);

    ori_nproc_max = rl.rlim_max;
    rl.rlim_cur = nproc_max;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        perror("setrlimit failed");
        return 1;
    }

    printf("New NPROC limit: soft=%lu\n", rl.rlim_cur);

    std::vector<pid_t> children;

    // 循环创建子进程直到失败
    while (true) {
        pid_t pid = fork();
        if (pid < 0) {
            // fork 失败
            printf("fork() failed after %d processes: %s\n", count, strerror(errno));
            break;
        } else if (pid == 0) {
            sleep(30);
            exit(0);
        } else {
            // 父进程
            count++;
            children.push_back(pid);
            printf("Created child process #%d (PID: %d)\n", count, pid);
        }
    }

    if (after_fork_fail) {
        after_fork_fail();
    }

    printf("Cleaning up child processes...\n");
    for (const int i : children) {
        kill(i, SIGKILL);
    }
    test::wait_all_child_processes();

    rl.rlim_cur = ori_nproc_max;
    // 恢复 NPROC 限制
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        perror("setrlimit failed");
        return 1;
    }

    return 0;
}

#if 0
TEST(base, fork_fail) {
    auto status = test::spawn_exec_and_wait([]() {
        if (geteuid() == 0) {
            Server::worker_set_isolation("nobody", "nobody", "");
        }
        ASSERT_EQ(test_fork_fail([]() {
                      pid_t pid;
                      auto pipe_fd = swoole_shell_exec("sleep 10", &pid, 0);
                      ASSERT_EQ(pipe_fd, -1);
                  }),
                  0);
        ASSERT_ERREQ(EAGAIN);
    });

    ASSERT_EQ(status, 0);
}
#endif

TEST(base, undefined_behavior) {
    swoole_init();  // no effect
    delete SwooleG.logger;
    SwooleG.logger = nullptr;  // avoid double free in swoole_shutdown()
    ASSERT_EQ(swoole_get_log_level(), SW_LOG_NONE);
    SwooleG.logger = new Logger();
}
