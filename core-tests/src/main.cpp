#include "test_core.h"
#include "swoole_memory.h"

using namespace swoole;
using namespace std;

static string root_path;
static int *test_counter;

static void init_root_path(const char *);

int main(int argc, char **argv) {
    swoole_init();
    init_root_path(argv[0]);

    if (getenv("DISPLAY_BACKTRACE") != nullptr) {
        sw_logger()->display_backtrace();
    }

#ifdef SW_VERBOSE
    swoole_set_log_level(SW_LOG_TRACE);
    swoole_set_trace_flags(SW_TRACE_ALL);
#endif

    if (getenv("VERBOSE") != nullptr && std::string(getenv("VERBOSE")) == "0") {
        swoole_set_log_level(SW_LOG_INFO);
        test::debug_output = test::null_stream;
    }

    test_counter = static_cast<int *>(sw_mem_pool()->alloc(sizeof(int) * TEST_COUNTER_NUM));

    ::testing::InitGoogleTest(&argc, argv);
    int retval = RUN_ALL_TESTS();

    swoole_clean();

    return retval;
}

static void init_root_path(const char *_exec_file) {
    char buf[PATH_MAX];
    string file;
    if (_exec_file[0] == '/') {
        file = _exec_file;
    } else {
        char *dir = getcwd(buf, sizeof(buf));
        file = string(dir) + "/" + _exec_file;
    }
    string relative_root_path = file.substr(0, file.rfind('/')) + "/../../";
    char *_realpath = realpath(relative_root_path.c_str(), buf);
    if (_realpath == nullptr) {
        root_path = relative_root_path;
    } else {
        root_path = string(_realpath);
    }
}

namespace swoole {
namespace test {
NullStream null_stream;
std::reference_wrapper<std::ostream> debug_output(std::cout);
void counter_init() {
    sw_memset_zero(test_counter, sizeof(int) * TEST_COUNTER_NUM);
}

int *counter_ptr() {
    return test_counter;
}

int counter_incr(int index, int add) {
    return sw_atomic_add_fetch(&test_counter[index], add);
}

int counter_get(int index) {
    return test_counter[index];
}

void counter_set(int index, int value) {
    test_counter[index] = value;
}

void counter_incr_and_put_log(int index, const char *msg) {
    DEBUG() << "PID: " << getpid() << ", VALUE: " << counter_incr(index) << "; " << msg << std::endl;
}

const string &get_root_path() {
    return root_path;
}

string get_ssl_dir() {
    return get_root_path() + "/tests/include/ssl_certs";
}

string get_jpg_file() {
    return root_path + TEST_JPG_FILE;
}

string http_get_request(const string &domain, const string &path) {
    return "GET " + path +
           " HTTP/1.1\r\n"
           "Host: " +
           domain +
           "\r\n"
           "Connection: close\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/51.0.2704.106 Safari/537.36"
           "\r\n\r\n";
}

bool is_github_ci() {
    return getenv("GITHUB_ACTIONS") != nullptr;
}

int exec_js_script(const std::string &file, const std::string &args) {
    std::string command = "bash -c 'node " + test::get_root_path() + "/core-tests/js/" + file + " " + args + "'";
    return std::system(command.c_str());
}

int get_random_port() {
    return TEST_PORT + swoole_system_random(1, 10000);
}

int wait_all_child_processes(bool verbose) {
    pid_t pid;
    int status;
    int count = 0;

    // 循环等待所有子进程结束
    while (true) {
        // 使用waitpid等待任意子进程，这里会阻塞直到有子进程退出
        pid = waitpid(-1, &status, 0);

        if (pid > 0) {
            // 成功回收一个子进程
            count++;

            // 输出子进程退出状态（如果启用详细输出）
            if (verbose) {
                if (WIFEXITED(status)) {
                    std::cout << "子进程 " << pid << " 正常退出，退出码: " << WEXITSTATUS(status) << std::endl;
                } else if (WIFSIGNALED(status)) {
                    std::cout << "子进程 " << pid << " 被信号 " << WTERMSIG(status) << " 终止";

                    if (WCOREDUMP(status)) {
                        std::cout << " (核心已转储)";
                    }

                    std::cout << std::endl;
                }
            }
        } else if (pid < 0) {
            if (errno == ECHILD) {
                // 没有子进程了，完成回收
                if (verbose) {
                    std::cout << "所有子进程已回收，共 " << count << " 个" << std::endl;
                }
                break;
            } else {
                // 其他错误
                if (verbose) {
                    perror("waitpid failed");
                }
                return -1;
            }
        }
    }

    return count;
}

// 检测子进程
int has_child_processes() {
    pid_t current_pid = getpid();
    DIR *proc_dir;
    struct dirent *entry;
    char stat_path[512];
    FILE *stat_file;
    char buffer[1024];
    pid_t pid, ppid;

    // 尝试使用waitpid快速检测
    if (waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD) {
        return 0;  // 没有子进程
    }

    // 如果waitpid没有明确结果，使用/proc检测
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc failed");
        return -1;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", entry->d_name);
            stat_file = fopen(stat_path, "r");
            if (stat_file) {
                if (fgets(buffer, sizeof(buffer), stat_file)) {
                    sscanf(buffer, "%d %*s %*c %d", &pid, &ppid);
                    if (ppid == current_pid) {
                        fclose(stat_file);
                        closedir(proc_dir);
                        return 1;  // 找到子进程
                    }
                }
                fclose(stat_file);
            }
        }
    }

    closedir(proc_dir);
    return 0;  // 没有子进程
}

// 检测线程
int has_threads() {
    FILE *status_file;
    char path[256];
    char line[256];
    int thread_count = -1;

    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    status_file = fopen(path, "r");
    if (!status_file) {
        perror("fopen failed");
        return -1;
    }

    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "Threads:", 8) == 0) {
            sscanf(line, "Threads: %d", &thread_count);
            break;
        }
    }

    fclose(status_file);
    return thread_count;
}

pid_t spawn_exec(const std::function<void(void)> &fn) {
    pid_t child_pid = fork();
    if (child_pid == -1) {
        throw std::system_error();
    } else if (child_pid == 0) {
        fn();
        exit(0);
    }
    return child_pid;
}

int spawn_exec_and_wait(const std::function<void(void)> &fn) {
    int status;
    pid_t pid = spawn_exec(fn);
    if (swoole_waitpid(pid, &status, 0) == pid) {
        return status;
    } else {
        return -1;
    }
}

}  // namespace test
}  // namespace swoole
