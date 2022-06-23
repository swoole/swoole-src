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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_server.h"
#include "swoole_http.h"
#include "swoole_mime_type.h"

#include <string>
#include <set>

namespace swoole {
namespace http_server {

class StaticHandler {
  private:
    Server *serv;
    std::string request_url;
    std::string dir_path;
    std::set<std::string> dir_files;
    std::string index_file;
    struct {
        off_t offset;
        size_t length;
        char filename[PATH_MAX];
    } task;

    size_t l_filename;
    struct stat file_stat;
    bool last;

  public:
    int status_code;
    StaticHandler(Server *_server, const char *url, size_t url_length) : request_url(url, url_length) {
        serv = _server;
        task.length = 0;
        task.offset = 0;
        last = false;
        status_code = 200;
        l_filename = 0;
        dir_path = "";
    }

    /**
     * @return true: continue to execute backwards
     * @return false: break static handler
     */
    bool hit();
    bool hit_index_file();

    bool is_modified(const std::string &date_if_modified_since);
    size_t make_index_page(String *buffer);
    bool get_dir_files();
    bool set_filename(std::string &filename);

    bool has_index_file() {
        return !index_file.empty();
    }

    bool is_enabled_auto_index() {
        return serv->http_autoindex;
    }

    std::string get_date();

    inline time_t get_file_mtime() {
#ifdef __MACH__
        return file_stat.st_mtimespec.tv_sec;
#else
        return file_stat.st_mtim.tv_sec;
#endif
    }

    std::string get_date_last_modified();

    inline const char *get_filename() {
        return task.filename;
    }

    inline const char *get_mimetype() {
        return swoole::mime_type::get(get_filename()).c_str();
    }

    inline std::string get_filename_std_string() {
        return std::string(task.filename, l_filename);
    }

    inline size_t get_filesize() {
        return file_stat.st_size;
    }

    inline const network::SendfileTask *get_task() {
        return (const network::SendfileTask *) &task;
    }

    inline bool is_dir() {
        return S_ISDIR(file_stat.st_mode);
    }
};

};  // namespace http_server
};  // namespace swoole
