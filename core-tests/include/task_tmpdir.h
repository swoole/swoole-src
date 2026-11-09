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

#pragma once

#include "swoole.h"

#ifndef _WIN32

#include <dirent.h>
#include <unistd.h>

#include <string>

namespace test {
class TaskTmpDirectory {
    std::string path_;

  public:
    TaskTmpDirectory() {
        char pattern[] = "/tmp/sw-task-XXXXXX";
        if (char *path = mkdtemp(pattern)) {
            path_ = path;
        }
    }
    ~TaskTmpDirectory() {
        if (path_.empty()) {
            return;
        }
        if (DIR *directory = opendir(path_.c_str())) {
            while (auto *entry = readdir(directory)) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    unlink((path_ + "/" + entry->d_name).c_str());
                }
            }
            closedir(directory);
        }
        rmdir(path_.c_str());
    }
    TaskTmpDirectory(const TaskTmpDirectory &) = delete;
    TaskTmpDirectory &operator=(const TaskTmpDirectory &) = delete;

    const std::string &path() const {
        return path_;
    }
    bool empty() const {
        DIR *directory = opendir(path_.c_str());
        if (!directory) {
            return false;
        }
        bool result = true;
        while (auto *entry = readdir(directory)) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                result = false;
                break;
            }
        }
        closedir(directory);
        return result;
    }
    void use_for_tasks() const {
        SwooleG.task_tmpfile = path_ + "/task.XXXXXX";
    }
};
}  // namespace test

#endif
