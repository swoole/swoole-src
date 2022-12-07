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
    typedef struct {
        off_t offset;
        size_t length;
        char part_header[SW_HTTP_SERVER_PART_HEADER];
    } task_t;
    std::vector<task_t> tasks;

    size_t l_filename = 0;
    char filename[PATH_MAX];
    struct stat file_stat;
    bool last = false;
    std::string content_type;
    std::string boundary;
    std::string end_part;
    size_t content_length = 0;

  public:
    int status_code = SW_HTTP_OK;
    StaticHandler(Server *_server, const char *url, size_t url_length) : request_url(url, url_length) {
        serv = _server;
    }

    /**
     * @return true: continue to execute backwards
     * @return false: break static handler
     */
    bool hit();
    bool hit_index_file();

    bool is_modified(const std::string &date_if_modified_since);
    bool is_modified_range(const std::string &date_range);
    size_t make_index_page(String *buffer);
    bool get_dir_files();
    bool set_filename(const std::string &filename);

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
        return filename;
    }

    inline const char *get_boundary() {
        if (boundary.empty()) {
            boundary = std::string(SW_HTTP_SERVER_BOUNDARY_PREKEY);
            swoole_random_string(boundary, SW_HTTP_SERVER_BOUNDARY_TOTAL_SIZE - sizeof(SW_HTTP_SERVER_BOUNDARY_PREKEY));
        }
        return boundary.c_str();
    }

    inline const char *get_content_type() {
        if (tasks.size() > 1) {
            content_type = std::string("multipart/byteranges; boundary=") + get_boundary();
            return content_type.c_str();
        } else {
            return get_mimetype();
        }
    }

    inline const char *get_mimetype() {
        return swoole::mime_type::get(get_filename()).c_str();
    }

    inline std::string get_filename_std_string() {
        return std::string(filename, l_filename);
    }

    inline size_t get_filesize() {
        return file_stat.st_size;
    }

    inline const std::vector<task_t> &get_tasks() {
        return tasks;
    }

    inline bool is_dir() {
        return S_ISDIR(file_stat.st_mode);
    }

    inline size_t get_content_length() {
        return content_length;
    }

    inline const char *get_end_part() {
        return end_part.c_str();
    }

    void parse_range(const char *range, const char *if_range);
};

};  // namespace http_server
};  // namespace swoole
