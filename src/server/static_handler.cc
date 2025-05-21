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

#include "swoole_static_handler.h"
#include "swoole_util.h"

#include <string>
#include <dirent.h>
#include <algorithm>
#include <sstream>

namespace swoole {

namespace http_server {
bool StaticHandler::is_modified(const std::string &date_if_modified_since) {
    char date_tmp[64];
    if (date_if_modified_since.empty() || date_if_modified_since.length() > sizeof(date_tmp) - 1) {
        return false;
    }

    struct tm tm3 {};
    memcpy(date_tmp, date_if_modified_since.c_str(), date_if_modified_since.length());
    date_tmp[date_if_modified_since.length()] = 0;

    const char *date_format = nullptr;

    if (strptime(date_tmp, SW_HTTP_RFC1123_DATE_GMT, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC1123_DATE_GMT;
    } else if (strptime(date_tmp, SW_HTTP_RFC1123_DATE_UTC, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC1123_DATE_UTC;
    } else if (strptime(date_tmp, SW_HTTP_RFC850_DATE, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC850_DATE;
    } else if (strptime(date_tmp, SW_HTTP_ASCTIME_DATE, &tm3) != nullptr) {
        date_format = SW_HTTP_ASCTIME_DATE;
    }
    return date_format && mktime(&tm3) - (time_t) serv->timezone_ >= get_file_mtime();
}

bool StaticHandler::is_modified_range(const std::string &date_range) {
    if (date_range.empty()) {
        return false;
    }

    tm tm3{};
    const char *date_format = nullptr;

    if (strptime(date_range.c_str(), SW_HTTP_RFC1123_DATE_GMT, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC1123_DATE_GMT;
    } else if (strptime(date_range.c_str(), SW_HTTP_RFC1123_DATE_UTC, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC1123_DATE_UTC;
    } else if (strptime(date_range.c_str(), SW_HTTP_RFC850_DATE, &tm3) != nullptr) {
        date_format = SW_HTTP_RFC850_DATE;
    } else if (strptime(date_range.c_str(), SW_HTTP_ASCTIME_DATE, &tm3) != nullptr) {
        date_format = SW_HTTP_ASCTIME_DATE;
    }
    time_t file_mtime = get_file_mtime();
    tm *tm_file_mtime = gmtime(&file_mtime);
    return date_format && mktime(&tm3) != mktime(tm_file_mtime);
}

std::string StaticHandler::get_date() {
    char date_[64];
    time_t now = ::time(nullptr);
    tm *tm1 = gmtime(&now);
    strftime(date_, sizeof(date_), "%a, %d %b %Y %H:%M:%S %Z", tm1);
    return date_;
}

std::string StaticHandler::get_date_last_modified() {
    char date_last_modified[64];
    time_t file_mtime = get_file_mtime();
    tm *tm2 = gmtime(&file_mtime);
    strftime(date_last_modified, sizeof(date_last_modified), "%a, %d %b %Y %H:%M:%S %Z", tm2);
    return date_last_modified;
}

bool StaticHandler::get_absolute_path() {
    char abs_path[PATH_MAX];
    if (!realpath(filename, abs_path)) {
        return false;
    }
    strncpy(filename, abs_path, sizeof(abs_path));
    l_filename = strlen(filename);
    return true;
}

bool StaticHandler::hit() {
    char *p = filename;
    const char *url = request_url.c_str();
    size_t url_length = request_url.length();
    /**
     * discard the url parameter
     * [/test.jpg?version=1#position] -> [/test.jpg]
     */
    auto params = (char *) memchr(url, '?', url_length);
    if (params == nullptr) {
        params = (char *) memchr(url, '#', url_length);
    }
    size_t n = params ? params - url : url_length;

    const std::string &document_root = serv->get_document_root();
    const size_t l_document_root = document_root.length();

    memcpy(p, document_root.c_str(), l_document_root);
    p += l_document_root;

    if (!serv->locations->empty()) {
        for (const auto &i : *serv->locations) {
            if (swoole_str_istarts_with(url, url_length, i.c_str(), i.size())) {
                last = true;
            }
        }
        if (!last) {
            return false;
        }
    }

    if (l_document_root + n >= PATH_MAX) {
        return catch_error();
    }

    memcpy(p, url, n);
    p += n;
    *p = '\0';
    if (!dir_path.empty()) {
        dir_path.clear();
    }
    dir_path = std::string(url, n);

    l_filename = url_decode(filename, p - filename);
    filename[l_filename] = '\0';

    // The file does not exist
    if (lstat(filename, &file_stat) < 0) {
        return catch_error();
    }

    // The filename is relative path, allows for the resolution of symbolic links.
    // This path is formed by concatenating the document root and that is permitted for access.
    if (is_absolute_path()) {
        if (is_link()) {
            // Use the realpath function to resolve a symbolic link to its actual path.
            if (!get_absolute_path()) {
                return catch_error();
            }
            if (lstat(filename, &file_stat) < 0) {
                return catch_error();
            }
        }
    } else {
        if (!get_absolute_path() || !is_located_in_document_root()) {
            return catch_error();
        }
    }

    if (serv->http_index_files && !serv->http_index_files->empty() && is_dir()) {
        return true;
    }

    if (serv->http_autoindex && is_dir()) {
        return true;
    }

    if (!mime_type::exists(filename) && !last) {
        return false;
    }

    if (!is_file()) {
        return false;
    }

    return true;
}

bool StaticHandler::hit_index_file() {
    if (serv->http_index_files && !serv->http_index_files->empty() && is_dir()) {
        if (!get_dir_files()) {
            return false;
        }
        index_file = intersection(*serv->http_index_files, dir_files);

        if (has_index_file() && !set_filename(index_file)) {
            return false;
        }
        if (!has_index_file() && !is_enabled_auto_index()) {
            return false;
        }
    }
    return true;
}

size_t StaticHandler::make_index_page(String *buffer) {
    get_dir_files();

    if (dir_path.back() != '/') {
        dir_path.append("/");
    }

    buffer->format_impl(String::FORMAT_APPEND | String::FORMAT_GROW,
                        "<html>\n"
                        "<head>\n"
                        "\t<meta charset='UTF-8'>\n<title>Index of %s</title>"
                        "</head>\n"
                        "<body>\n" SW_HTTP_PAGE_CSS "<h1>Index of %s</h1>"
                        "\t<ul>\n",
                        dir_path.c_str(),
                        dir_path.c_str());

    for (const auto &dir_file : dir_files) {
        if (dir_file == "." || (dir_path == "/" && dir_file == "..")) {
            continue;
        }
        buffer->format_impl(String::FORMAT_APPEND | String::FORMAT_GROW,
                            "\t\t<li><a href=%s%s>%s</a></li>\n",
                            dir_path.c_str(),
                            dir_file.c_str(),
                            dir_file.c_str());
    }

    buffer->append(SW_STRL("\t</ul>\n" SW_HTTP_POWER_BY "</body>\n</html>\n"));

    return buffer->length;
}

bool StaticHandler::get_dir_files() {
    if (!dir_files.empty()) {
        return true;
    }

    if (!is_dir()) {
        return false;
    }

    DIR *dir = opendir(filename);
    if (dir == nullptr) {
        return false;
    }

    struct dirent *ptr;
    while ((ptr = readdir(dir)) != nullptr) {
        dir_files.insert(ptr->d_name);
    }

    closedir(dir);

    return true;
}

bool StaticHandler::set_filename(const std::string &_filename) {
    char *p = filename + l_filename;

    if (*p != '/') {
        *p = '/';
        p += 1;
    }

    memcpy(p, _filename.c_str(), _filename.length());
    p += _filename.length();
    *p = 0;

    if (lstat(filename, &file_stat) < 0) {
        return false;
    }

    if (!is_file()) {
        return false;
    }

    return true;
}

void StaticHandler::parse_range(const char *range, const char *if_range) {
    task_t _task{};
    _task.length = 0;
    // range
    if (range && '\0' != *range) {
        const char *p = range;
        // bytes=
        if (!SW_STR_ISTARTS_WITH(p, strlen(range), "bytes=")) {
            _task.offset = 0;
            _task.length = content_length = get_filesize();
            tasks.push_back(_task);
            return;
        }
        p += 6;
        size_t start, end, size = 0, cutoff = SIZE_MAX / 10, cutlim = SIZE_MAX % 10, suffix,
                           _content_length = get_filesize();
        content_length = 0;
        for (;;) {
            start = 0;
            end = 0;
            suffix = 0;

            while (*p == ' ') {
                p++;
            }

            if (*p != '-') {
                if (*p < '0' || *p > '9') {
                    status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                    return;
                }

                while (*p >= '0' && *p <= '9') {
                    if (start >= cutoff && (start > cutoff || (size_t) (*p - '0') > cutlim)) {
                        status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                        return;
                    }

                    start = start * 10 + (*p++ - '0');
                }

                while (*p == ' ') {
                    p++;
                }

                if (*p++ != '-') {
                    status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                    return;
                }

                while (*p == ' ') {
                    p++;
                }

                if (*p == ',' || *p == '\0') {
                    end = _content_length;
                    goto found;
                }

            } else {
                suffix = 1;
                p++;
            }

            if (*p < '0' || *p > '9') {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }

            while (*p >= '0' && *p <= '9') {
                if (end >= cutoff && (end > cutoff || (size_t) (*p - '0') > cutlim)) {
                    status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                    return;
                }

                end = end * 10 + (*p++ - '0');
            }

            while (*p == ' ') {
                p++;
            }

            if (*p != ',' && *p != '\0' && *p != '\r') {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }

            if (suffix) {
                start = (end < _content_length) ? _content_length - end : 0;
                end = _content_length - 1;
            }

            if (end >= _content_length) {
                end = _content_length;

            } else {
                end++;
            }

        found:
            if (start < end) {
                if (size > SIZE_MAX - (end - start)) {
                    status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                    return;
                }
                size += end - start;
                _task.offset = start;
                _task.length = end - start;
                content_length += sw_snprintf(_task.part_header,
                                              sizeof(_task.part_header),
                                              "%s--%s\r\n"
                                              "Content-Type: %s\r\n"
                                              "Content-Range: bytes %zu-%zu/%zu\r\n\r\n",
                                              tasks.empty() ? "" : "\r\n",
                                              get_boundary().c_str(),
                                              get_mimetype().c_str(),
                                              _task.offset,
                                              end - 1,
                                              get_filesize()) +
                                  _task.length;
                tasks.push_back(_task);
            } else if (start == 0) {
                break;
            }

            if (*p++ != ',' || '\r' == *p || '\0' == *p) {
                break;
            }
        }
    }
    if (_task.length > 0) {
        if (1 == tasks.size()) {
            content_length = _task.length;
        } else {
            end_part = std::string("\r\n--") + get_boundary() + "--\r\n";
            content_length += end_part.size();
        }
        status_code = SW_HTTP_PARTIAL_CONTENT;
    } else {
        _task.offset = 0;
        _task.length = content_length = get_filesize();
        tasks.push_back(_task);
    }
    // if-range
    if (if_range) {
        if (is_modified_range(if_range)) {
            tasks.clear();
            _task.offset = 0;
            _task.length = content_length = get_filesize();
            tasks.push_back(_task);
            status_code = SW_HTTP_OK;
        }
    }
}
}  // namespace http_server
void Server::add_static_handler_location(const std::string &location) {
    if (locations == nullptr) {
        locations = std::make_shared<std::unordered_set<std::string>>();
    }
    locations->emplace(location);
}

void Server::add_static_handler_index_files(const std::string &file) {
    if (http_index_files == nullptr) {
        http_index_files = std::make_shared<std::vector<std::string>>();
    }

    auto iter = std::find(http_index_files->begin(), http_index_files->end(), file);
    if (iter == http_index_files->end()) {
        http_index_files->emplace_back(file);
    }
}

bool Server::select_static_handler(http_server::Request *request, Connection *conn) {
    const char *url = request->buffer_->str + request->url_offset_;
    size_t url_length = request->url_length_;

    http_server::StaticHandler handler(this, url, url_length);
    if (!handler.hit()) {
        return false;
    }

    char header_buffer[1024];
    SendData response;
    response.info.fd = conn->session_id;
    response.info.type = SW_SERVER_EVENT_SEND_DATA;

    if (handler.status_code == SW_HTTP_NOT_FOUND) {
        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 %s\r\n"
                                        "Server: " SW_HTTP_SERVER_SOFTWARE "\r\n"
                                        "Content-Length: %zu\r\n"
                                        "\r\n%s",
                                        http_server::get_status_message(SW_HTTP_NOT_FOUND),
                                        sizeof(SW_HTTP_PAGE_404) - 1,
                                        SW_HTTP_PAGE_404);
        response.data = header_buffer;
        send_to_connection(&response);

        return true;
    }

    auto date_str = handler.get_date();
    auto date_str_last_modified = handler.get_date_last_modified();

    std::string date_if_modified_since = request->get_header("If-Modified-Since");
    if (!date_if_modified_since.empty() && handler.is_modified(date_if_modified_since)) {
        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 304 Not Modified\r\n"
                                        "Connection: %s\r\n"
                                        "Date: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Server: %s\r\n\r\n",
                                        request->keep_alive ? "keep-alive" : "close",
                                        date_str.c_str(),
                                        date_str_last_modified.c_str(),
                                        SW_HTTP_SERVER_SOFTWARE);
        response.data = header_buffer;
        send_to_connection(&response);

        return true;
    }

    /**
     * if http_index_files is enabled, need to search the index file first.
     * if the index file is found, set filename to index filename.
     */
    if (!handler.hit_index_file()) {
        return false;
    }

    /**
     * the index file was not found in the current directory,
     * if http_autoindex is enabled, should show the list of files in the current directory.
     */
    if (!handler.has_index_file() && handler.is_enabled_auto_index() && handler.is_dir()) {
        sw_tg_buffer()->clear();
        size_t body_length = handler.make_index_page(sw_tg_buffer());

        response.info.len = sw_snprintf(header_buffer,
                                        sizeof(header_buffer),
                                        "HTTP/1.1 200 OK\r\n"
                                        "Connection: %s\r\n"
                                        "Content-Length: %ld\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Date: %s\r\n"
                                        "Last-Modified: %s\r\n"
                                        "Server: %s\r\n\r\n",
                                        request->keep_alive ? "keep-alive" : "close",
                                        static_cast<long>(body_length),
                                        date_str.c_str(),
                                        date_str_last_modified.c_str(),
                                        SW_HTTP_SERVER_SOFTWARE);
        response.data = header_buffer;
        send_to_connection(&response);

        response.info.len = body_length;
        response.data = sw_tg_buffer()->str;
        send_to_connection(&response);
        return true;
    }

    handler.parse_range(request->get_header("Range").c_str(), request->get_header("If-Range").c_str());
    auto tasks = handler.get_tasks();

    std::stringstream header_stream;
    if (1 == tasks.size()) {
        if (SW_HTTP_PARTIAL_CONTENT == handler.status_code) {
            header_stream << "Content-Range: bytes " << tasks[0].offset << "-"
                          << (tasks[0].length + tasks[0].offset - 1) << "/" << handler.get_filesize() << "\r\n";
        } else {
            header_stream << "Accept-Ranges: bytes\r\n";
        }
    }

    response.info.len = sw_snprintf(
        header_buffer,
        sizeof(header_buffer),
        "HTTP/1.1 %s\r\n"
        "Connection: %s\r\n"
        "Content-Length: %ld\r\n"
        "Content-Type: %s\r\n"
        "%s"
        "Date: %s\r\n"
        "Last-Modified: %s\r\n"
        "Server: %s\r\n\r\n",
        http_server::get_status_message(handler.status_code),
        request->keep_alive ? "keep-alive" : "close",
        SW_HTTP_HEAD == request->method ? 0 : handler.get_content_length(),
        SW_HTTP_HEAD == request->method ? handler.get_mimetype().c_str() : handler.get_content_type().c_str(),
        header_stream.str().c_str(),
        date_str.c_str(),
        date_str_last_modified.c_str(),
        SW_HTTP_SERVER_SOFTWARE);

    response.data = header_buffer;

    // Use tcp_nopush to improve sending efficiency
    conn->socket->cork();

    // Send HTTP header
    send_to_connection(&response);

    // Send HTTP body
    if (SW_HTTP_HEAD != request->method) {
        if (!tasks.empty()) {
            size_t task_size = sizeof(network::SendfileTask) + strlen(handler.get_filename()) + 1;
            auto task = static_cast<network::SendfileTask *>(sw_malloc(task_size));
            strcpy(task->filename, handler.get_filename());
            if (tasks.size() > 1) {
                for (const auto &i : tasks) {
                    response.info.type = SW_SERVER_EVENT_SEND_DATA;
                    response.info.len = strlen(i.part_header);
                    response.data = i.part_header;
                    send_to_connection(&response);

                    task->offset = i.offset;
                    task->length = i.length;
                    response.info.type = SW_SERVER_EVENT_SEND_FILE;
                    response.info.len = task_size;
                    response.data = reinterpret_cast<char *>(task);
                    send_to_connection(&response);
                }

                response.info.type = SW_SERVER_EVENT_SEND_DATA;
                response.info.len = handler.get_end_part().length();
                response.data = handler.get_end_part().c_str();
                send_to_connection(&response);
            } else if (tasks[0].length > 0) {
                task->offset = tasks[0].offset;
                task->length = tasks[0].length;
                response.info.type = SW_SERVER_EVENT_SEND_FILE;
                response.info.len = task_size;
                response.data = reinterpret_cast<char *>(task);
                send_to_connection(&response);
            }
            sw_free(task);
        }
    }

    // Close the connection if keepalive is not used
    if (!request->keep_alive) {
        response.info.type = SW_SERVER_EVENT_CLOSE;
        response.info.len = 0;
        response.data = nullptr;
        send_to_connection(&response);
    }

    return true;
}
}  // namespace swoole
