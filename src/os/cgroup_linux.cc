/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"

#include <cerrno>
#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <vector>

#ifdef __linux__
namespace {
struct CgroupInfo {
    int version = 0;
    std::string path;
};

struct MountInfo {
    std::string root;
    std::string mount_point;
};

static std::vector<std::string> split(const std::string &input, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(input);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        parts.emplace_back(std::move(item));
    }
    return parts;
}

static bool has_controller(const std::string &controllers, const char *target) {
    for (const auto &controller : split(controllers, ',')) {
        if (controller == target) {
            return true;
        }
    }
    return false;
}

static bool read_first_line(const std::string &path, std::string *line) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    return static_cast<bool>(std::getline(file, *line));
}

static bool has_path_prefix(const std::string &path, const std::string &prefix) {
    auto size = prefix.length();
    if (size == 1 && prefix[0] == '/') {
        return true;
    }
    if (path.length() < size || path.compare(0, size, prefix) != 0) {
        return false;
    }
    return path.length() == size || path[size] == '/';
}

static size_t unescaped_len(const std::string &path) {
    size_t count = 0;

    for (size_t i = 0; i < path.length(); i++) {
        if (path[i] == '\\' && i + 3 < path.length()) {
            count += 1;
            i += 3;
        } else {
            count += 1;
        }
    }
    return count;
}

static bool unescape_path(const std::string &input, std::string *output) {
    output->clear();
    output->reserve(unescaped_len(input));

    for (size_t i = 0; i < input.length();) {
        auto c = input[i];
        if (c != '\\') {
            output->push_back(c);
            i++;
            continue;
        }

        if (i + 3 >= input.length()) {
            return false;
        }

        int value = 0;
        for (size_t j = 1; j <= 3; j++) {
            auto digit = input[i + j];
            if (digit < '0' || digit > '7') {
                return false;
            }
            value = value * 8 + (digit - '0');
        }

        output->push_back(static_cast<char>(value));
        i += 4;
    }

    return true;
}

static int get_affinity_cpu_num() {
    // Match Go runtime getCPUCount: scan a large affinity bitmask so high-CPU
    // systems are not truncated by cpu_set_t / CPU_SETSIZE.
    constexpr size_t kMaxCPUs = 64 * 1024;
    unsigned char buf[kMaxCPUs / 8];

    auto size = syscall(SYS_sched_getaffinity, 0, sizeof(buf), buf);
    if (size > 0) {
        int count = 0;

        for (long i = 0; i < size; i++) {
            auto value = buf[i];
            while (value != 0) {
                count += value & 1;
                value >>= 1;
            }
        }
        if (count > 0) {
            return count;
        }
    }

    auto cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    return cpu_num > 0 ? static_cast<int>(cpu_num) : 1;
}

static bool get_cgroup_v2(CgroupInfo *info) {
    std::ifstream file("/proc/self/cgroup");
    std::string line;

    while (std::getline(file, line)) {
        auto first = line.find(':');
        if (first == std::string::npos) {
            continue;
        }
        auto second = line.find(':', first + 1);
        if (second == std::string::npos) {
            continue;
        }
        if (line.substr(first + 1, second - first - 1).empty()) {
            info->version = 2;
            info->path = line.substr(second + 1);
            return !info->path.empty();
        }
    }

    return false;
}

static bool get_cgroup_v1(CgroupInfo *info) {
    std::ifstream file("/proc/self/cgroup");
    std::string line;

    while (std::getline(file, line)) {
        auto first = line.find(':');
        if (first == std::string::npos) {
            continue;
        }
        auto second = line.find(':', first + 1);
        if (second == std::string::npos) {
            continue;
        }

        auto controllers = line.substr(first + 1, second - first - 1);
        if (has_controller(controllers, "cpu")) {
            info->version = 1;
            info->path = line.substr(second + 1);
            return !info->path.empty();
        }
    }

    return false;
}

static bool get_cgroup_info(CgroupInfo *info) {
    if (get_cgroup_v2(info)) {
        return true;
    }
    return get_cgroup_v1(info);
}

static bool get_mount_info(const CgroupInfo &cgroup, MountInfo *mount_info) {
    std::ifstream file("/proc/self/mountinfo");
    std::string line;

    while (std::getline(file, line)) {
        auto fields = split(line, ' ');
        if (fields.size() < 10) {
            continue;
        }

        size_t sep = std::numeric_limits<size_t>::max();
        for (size_t i = 6; i < fields.size(); i++) {
            if (fields[i] == "-") {
                sep = i;
                break;
            }
        }
        if (sep == std::numeric_limits<size_t>::max() || sep + 3 >= fields.size()) {
            continue;
        }

        auto root = fields[3];
        auto mount_point = fields[4];
        auto fs_type = fields[sep + 1];

        if (root.empty() || root[0] != '/') {
            continue;
        }
        if (cgroup.version == 2) {
            if (fs_type != "cgroup2") {
                continue;
            }
        } else {
            if (fs_type != "cgroup" || !has_controller(fields[sep + 3], "cpu")) {
                continue;
            }
        }

        std::string unescaped_root;
        std::string unescaped_mount_point;
        if (!unescape_path(root, &unescaped_root) || !unescape_path(mount_point, &unescaped_mount_point)) {
            continue;
        }
        if (!has_path_prefix(cgroup.path, unescaped_root)) {
            continue;
        }

        auto relative = cgroup.path.substr(unescaped_root.length());
        if (unescaped_root == "/" && cgroup.path != "/") {
            relative = cgroup.path;
        }
        if (has_path_prefix(relative, "/..")) {
            continue;
        }

        mount_info->root = std::move(unescaped_root);
        mount_info->mount_point = std::move(unescaped_mount_point);
        return true;
    }

    return false;
}

static std::string get_cgroup_dir(const CgroupInfo &cgroup, const MountInfo &mount_info) {
    if (!has_path_prefix(cgroup.path, mount_info.root)) {
        return "";
    }

    auto relative = cgroup.path.substr(mount_info.root.length());
    if (mount_info.root == "/" && cgroup.path != "/") {
        relative = cgroup.path;
    }
    if (has_path_prefix(relative, "/..")) {
        return "";
    }
    if (relative.empty() || relative == "/") {
        return mount_info.mount_point;
    }
    return mount_info.mount_point + relative;
}

static bool parse_int64(const std::string &value, int64_t *result) {
    char *end = nullptr;
    errno = 0;
    auto parsed = strtoll(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0') {
        return false;
    }
    *result = parsed;
    return true;
}

static int quota_to_cpu_num(int64_t quota, int64_t period) {
    if (quota <= 0 || period <= 0) {
        return 0;
    }
    auto cpu_limit = static_cast<double>(quota) / static_cast<double>(period);
    auto cpu_num = static_cast<int>(std::ceil(cpu_limit));
    return SW_MAX(cpu_num, 2);
}

static int get_cgroup_cpu_num_v1(const std::string &dir) {
    std::string quota_line;
    std::string period_line;
    int64_t quota = 0;
    int64_t period = 0;

    if (!read_first_line(dir + "/cpu.cfs_quota_us", &quota_line) || !parse_int64(quota_line, &quota)) {
        return 0;
    }
    if (quota < 0) {
        return 0;
    }
    if (!read_first_line(dir + "/cpu.cfs_period_us", &period_line) || !parse_int64(period_line, &period)) {
        return 0;
    }

    return quota_to_cpu_num(quota, period);
}

static int get_cgroup_cpu_num_v2(const std::string &dir) {
    std::string line;
    std::string quota_str;
    std::string period_str;
    int64_t quota = 0;
    int64_t period = 0;

    if (!read_first_line(dir + "/cpu.max", &line)) {
        return 0;
    }

    std::istringstream iss(line);
    if (!(iss >> quota_str >> period_str)) {
        return 0;
    }
    if (quota_str == "max") {
        return 0;
    }
    if (!parse_int64(quota_str, &quota) || !parse_int64(period_str, &period)) {
        return 0;
    }

    return quota_to_cpu_num(quota, period);
}

static int get_cgroup_cpu_num() {
    CgroupInfo cgroup;
    MountInfo mount_info;

    if (!get_cgroup_info(&cgroup) || !get_mount_info(cgroup, &mount_info)) {
        return 0;
    }

    auto dir = get_cgroup_dir(cgroup, mount_info);
    if (dir.empty()) {
        return 0;
    }

    if (cgroup.version == 2) {
        return get_cgroup_cpu_num_v2(dir);
    }
    if (cgroup.version == 1) {
        return get_cgroup_cpu_num_v1(dir);
    }
    return 0;
}

}  // namespace
#endif

int swoole_get_available_cpu_num() {
#ifdef __linux__
    auto cpu_num = get_affinity_cpu_num();
    auto cgroup_cpu_num = get_cgroup_cpu_num();

    if (cgroup_cpu_num > 0) {
        cpu_num = SW_MIN(cpu_num, cgroup_cpu_num);
    }
    return SW_MAX(1, cpu_num);
#else
    auto cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    return cpu_num > 0 ? static_cast<int>(cpu_num) : 1;
#endif
}

