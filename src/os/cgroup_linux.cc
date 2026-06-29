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
#include <sstream>
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

static int get_affinity_cpu_num() {
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    if (sched_getaffinity(getpid(), sizeof(cpu_set), &cpu_set) == 0) {
        auto count = CPU_COUNT(&cpu_set);
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
        auto separator = line.find(" - ");
        if (separator == std::string::npos) {
            continue;
        }

        auto left = split(line.substr(0, separator), ' ');
        auto right = split(line.substr(separator + 3), ' ');
        if (left.size() < 5 || right.size() < 3) {
            continue;
        }

        auto &fs_type = right[0];
        auto &super_options = right[2];

        if (cgroup.version == 2) {
            if (fs_type != "cgroup2") {
                continue;
            }
        } else {
            if (fs_type != "cgroup" || !has_controller(super_options, "cpu")) {
                continue;
            }
        }

        mount_info->root = left[3];
        mount_info->mount_point = left[4];
        return true;
    }

    return false;
}

static std::string get_cgroup_dir(const CgroupInfo &cgroup, const MountInfo &mount_info) {
    std::string relative = cgroup.path;

    if (relative.empty()) {
        return "";
    }
    if (relative[0] != '/') {
        relative.insert(relative.begin(), '/');
    }
    if (mount_info.root != "/" && !mount_info.root.empty()) {
        if (relative.compare(0, mount_info.root.length(), mount_info.root) != 0) {
            return "";
        }
        relative.erase(0, mount_info.root.length());
        if (relative.empty()) {
            relative = "/";
        }
    }

    if (relative == "/") {
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

    // Be conservative for default worker/thread sizing: 1.9 CPUs still maps to 1.
    auto cpu_num = static_cast<int>(quota / period);
    return cpu_num > 0 ? cpu_num : 1;
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
