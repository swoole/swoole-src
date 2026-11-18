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
#include <memory>
#include <cctype>
#include <regex>

namespace swoole {
namespace http_server {
static std::string html_escape(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.length());

    for (const char c : value) {
        switch (c) {
        case '&':
            escaped.append("&amp;");
            break;
        case '<':
            escaped.append("&lt;");
            break;
        case '>':
            escaped.append("&gt;");
            break;
        case '"':
            escaped.append("&quot;");
            break;
        case '\'':
            escaped.append("&#39;");
            break;
        default:
            escaped.push_back(c);
            break;
        }
    }

    return escaped;
}

static std::string percent_encode_path_segment(const std::string &value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string encoded;
    encoded.reserve(value.length());

    for (const unsigned char c : value) {
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            encoded.push_back(c);
        } else {
            encoded.push_back('%');
            encoded.push_back(hex[c >> 4]);
            encoded.push_back(hex[c & 0x0f]);
        }
    }

    return encoded;
}

static bool parse_http_date(const std::string &value, time_t &result) {
    if (value.empty() || value.length() > 63 || value.find('\0') != std::string::npos) {
        return false;
    }
    static const char *formats[] = {
        SW_HTTP_RFC1123_DATE_GMT, SW_HTTP_RFC1123_DATE_UTC, SW_HTTP_RFC850_DATE, SW_HTTP_ASCTIME_DATE};
    for (const auto *format : formats) {
        tm parsed{};
        const char *end = strptime(value.c_str(), format, &parsed);
        if (!end || *end) {
            continue;
        }
        result = make_utc_time(parsed);
        const tm check = get_utc_tm(result);
        // Reject dates normalized by the calendar conversion (for example February 31).
        if (check.tm_year == parsed.tm_year && check.tm_mon == parsed.tm_mon && check.tm_mday == parsed.tm_mday &&
            check.tm_hour == parsed.tm_hour && check.tm_min == parsed.tm_min && check.tm_sec == parsed.tm_sec) {
            return true;
        }
    }
    return false;
}

static bool match_etag(const std::string &value, const std::string &etag, bool weak) {
    size_t pos = 0;
    while (pos < value.length()) {
        while (pos < value.length() && (value[pos] == ' ' || value[pos] == '\t')) {
            ++pos;
        }
        if (pos == value.length()) {
            return false;
        }
        if (value[pos] == '*') {
            ++pos;
            while (pos < value.length() && (value[pos] == ' ' || value[pos] == '\t')) {
                ++pos;
            }
            return pos == value.length();
        }
        const bool weak_tag = value.compare(pos, 2, "W/") == 0;
        if (weak_tag) {
            pos += 2;
        }
        if (pos >= value.length() || value[pos] != '"') {
            return false;
        }
        const size_t start = pos++;
        const size_t end = value.find('"', pos);
        if (end == std::string::npos) {
            return false;
        }
        pos = end + 1;
        const bool matches = (!weak_tag || weak) && value.compare(start, pos - start, etag) == 0;
        while (pos < value.length() && (value[pos] == ' ' || value[pos] == '\t')) {
            ++pos;
        }
        if (pos < value.length() && value[pos] != ',') {
            return false;
        }
        if (matches) {
            return true;
        }
        if (pos < value.length()) {
            ++pos;
        }
    }
    return false;
}

std::string StaticHandler::get_etag() const {
    // Metadata-based validator, like common static servers; no file-content hash
    // or per-request reads are needed. Nanoseconds distinguish subsecond updates.
    long nanoseconds = 0;
#ifdef __MACH__
    nanoseconds = file_stat.st_mtimespec.tv_nsec;
#elif !defined(_WIN32)
    nanoseconds = file_stat.st_mtim.tv_nsec;
#endif
    char value[96];
    const int length = snprintf(value,
                                sizeof(value),
                                "\"%llx-%llx-%lx\"",
                                static_cast<unsigned long long>(get_file_mtime()),
                                static_cast<unsigned long long>(get_filesize()),
                                static_cast<unsigned long>(nanoseconds));
    return {value, static_cast<size_t>(length)};
}

int StaticHandler::evaluate_preconditions(const std::string &if_match,
                                          const std::string &if_unmodified_since,
                                          const std::string &if_none_match,
                                          const std::string &if_modified_since) const {
    // RFC 9110 section 13.2.2: entity tags take precedence over date validators.
    time_t date;
    if (!if_match.empty()) {
        if (!match_etag(if_match, get_etag(), false)) {
            return SW_HTTP_PRECONDITION_FAILED;
        }
    } else if (parse_http_date(if_unmodified_since, date) && get_file_mtime() > date) {
        return SW_HTTP_PRECONDITION_FAILED;
    }
    if (!if_none_match.empty()) {
        if (match_etag(if_none_match, get_etag(), true)) {
            return SW_HTTP_NOT_MODIFIED;
        }
    } else if (is_modified(if_modified_since)) {
        return SW_HTTP_NOT_MODIFIED;
    }
    return SW_HTTP_OK;
}

std::string StaticHandler::get_directory_redirect() const {
    if (!is_dir() || request_url != original_url) {
        return {};
    }
    const auto query = original_url.find_first_of("?#");
    const auto path = original_url.substr(0, query);
    if (path.empty() || path.back() == '/') {
        return {};
    }
    // A relative Location must not become a network-path reference (//host/).
    const auto first = path.find_first_not_of('/');
    std::string location = "/" + path.substr(first == std::string::npos ? path.length() : first) + "/";
    if (query != std::string::npos) {
        location += original_url.substr(query);
    }
    return location;
}

bool StaticHandler::is_modified(const std::string &date_if_modified_since) const {
    time_t date;
    return parse_http_date(date_if_modified_since, date) && date >= get_file_mtime();
}

bool StaticHandler::is_modified_range(const std::string &date_range) const {
    if (!date_range.empty() && date_range.front() == '"') {
        return date_range != get_etag();
    }
    time_t date;
    // If-Range requires a strong entity tag or an exactly matching HTTP-date.
    return !parse_http_date(date_range, date) || date != get_file_mtime();
}

std::string StaticHandler::get_date() {
    char date_[64];
    time_t now = ::time(nullptr);
    tm tm1 = get_utc_tm(now);
    strftime(date_, sizeof(date_), "%a, %d %b %Y %H:%M:%S %Z", &tm1);
    return date_;
}

std::string StaticHandler::get_date_last_modified() const {
    char date_last_modified[64];
    time_t file_mtime = get_file_mtime();
    tm tm2 = get_utc_tm(file_mtime);
    strftime(date_last_modified, sizeof(date_last_modified), "%a, %d %b %Y %H:%M:%S %Z", &tm2);
    return date_last_modified;
}

bool StaticHandler::get_absolute_path() {
    char abs_path[PATH_MAX];
    if (!realpath(filename, abs_path)) {
        return false;
    }

    size_t abs_path_len = strlen(abs_path);
    if (abs_path_len >= PATH_MAX) {
        return false;
    }
    memcpy(filename, abs_path, abs_path_len + 1);
    l_filename = abs_path_len;
    return true;
}

bool StaticHandler::try_serve() {
    serv->apply_rewrite_rules(this);

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

    if (!serv->locations->empty()) {
        for (const auto &location : *serv->locations) {
            if (swoole_str_istarts_with(url, url_length, location.c_str(), location.size())) {
                last = true;
                break;
            }
        }
        if (!last) {
            return false;
        }
    }
    if (l_document_root >= PATH_MAX || n >= PATH_MAX - l_document_root) {
        return catch_error();
    }
    memcpy(p, document_root.c_str(), l_document_root);
    p += l_document_root;
    const auto hex = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    // URI paths are not form data: '+' is literal, and only the URL is decoded.
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = url[i];
        if (c == '%') {
            if (i + 2 >= n || hex(url[i + 1]) < 0 || hex(url[i + 2]) < 0) {
                status_code = SW_HTTP_BAD_REQUEST;
                return true;
            }
            c = (hex(url[i + 1]) << 4) | hex(url[i + 2]);
            i += 2;
        }
        if (c == 0) {
            status_code = SW_HTTP_BAD_REQUEST;
            return true;
        }
        *p++ = c;
    }
    *p = '\0';
    dir_path.assign(url, n);
    l_filename = p - filename;

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

bool StaticHandler::try_serve_index_file() {
    if (serv->http_index_files && !serv->http_index_files->empty() && is_dir()) {
        // Index lookup is proportional to the configured candidates, not directory size.
        for (const auto &candidate : *serv->http_index_files) {
            if (set_filename(candidate)) {
                index_file = candidate;
                return true;
            }
        }
        return is_enabled_auto_index();
    }
    return true;
}

bool StaticHandler::open_file() {
    if (is_dir()) {
        return true;
    }
    auto opened = std::make_shared<File>(filename, File::READ | File::BINARY | File::NONBLOCK);
    struct stat opened_stat;
    if (!opened->ready() || !opened->stat(&opened_stat) || !S_ISREG(opened_stat.st_mode)) {
        return false;
    }
    // Validators and send tasks use this descriptor's metadata, not a later path lookup.
    file_stat = opened_stat;
    file = std::move(opened);
    return true;
}

size_t StaticHandler::make_index_page(String *buffer) {
    get_dir_files();

    if (dir_path.empty() || dir_path.back() != '/') {
        dir_path.append("/");
    }
    const std::string escaped_dir_path = html_escape(dir_path);

    buffer->format_impl(String::FORMAT_APPEND | String::FORMAT_GROW,
                        "<html>\n"
                        "<head>\n"
                        "\t<meta charset='UTF-8'>\n<title>Index of %s</title>"
                        "</head>\n"
                        "<body>\n" SW_HTTP_PAGE_CSS "<h1>Index of %s</h1>"
                        "\t<ul>\n",
                        escaped_dir_path.c_str(),
                        escaped_dir_path.c_str());

    for (const auto &dir_file : dir_files) {
        if (dir_file == "." || (dir_path == "/" && dir_file == "..")) {
            continue;
        }
        std::string escaped_href = escaped_dir_path + percent_encode_path_segment(dir_file);
        std::string escaped_name = html_escape(dir_file);

        buffer->format_impl(String::FORMAT_APPEND | String::FORMAT_GROW,
                            "\t\t<li><a href=\"%s\">%s</a></li>\n",
                            escaped_href.c_str(),
                            escaped_name.c_str());
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

    const auto close_dir = [](DIR *dir) { sw_closedir(dir); };
    std::unique_ptr<DIR, decltype(close_dir)> dir(sw_opendir(filename), close_dir);
    if (!dir) {
        return false;
    }

    while (auto *entry = sw_readdir(dir.get())) {
        dir_files.emplace(entry->d_name);
    }

    return true;
}

bool StaticHandler::set_filename(const std::string &name) {
    const size_t separator = l_filename && filename[l_filename - 1] == '/' ? 0 : 1;
    if (l_filename + separator + name.length() >= PATH_MAX) {
        return false;
    }
    std::string candidate(filename, l_filename);
    if (separator) {
        candidate += '/';
    }
    candidate += name;
    struct stat candidate_stat;
    if (::stat(candidate.c_str(), &candidate_stat) < 0 || !S_ISREG(candidate_stat.st_mode)) {
        return false;
    }
    // Failed candidates leave the directory intact for the next candidate/autoindex.
    memcpy(filename, candidate.c_str(), candidate.length() + 1);
    l_filename = candidate.length();
    file_stat = candidate_stat;
    return true;
}

void StaticHandler::parse_range(const char *range, const char *if_range) {
    // Publish a plan only after the complete header has been validated. A malformed
    // later range must never leave executable tasks or multipart lengths behind.
    tasks.clear();
    end_part.clear();
    content_length = 0;
    status_code = SW_HTTP_OK;
    const size_t file_size = get_filesize();
    const auto full_response = [&]() {
        task_t task{};
        task.length = content_length = file_size;
        tasks.clear();
        tasks.push_back(task);
        status_code = SW_HTTP_OK;
    };
    if (!range || !*range || !SW_STR_ISTARTS_WITH(range, strlen(range), "bytes=") || file_size == 0) {
        full_response();
        return;
    }

    if (if_range && *if_range && is_modified_range(if_range)) {
        full_response();
        return;
    }

    static constexpr size_t max_ranges = 16;
    size_t range_count = 0;
    size_t selected_bytes = 0;
    bool excessive = false;
    std::vector<task_t> ranges;
    const char *p = range + 6;
    const auto skip_space = [&]() {
        while (*p == ' ' || *p == '\t') {
            ++p;
        }
    };
    const auto number = [&](size_t &value) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        value = 0;
        do {
            const size_t digit = *p++ - '0';
            if (value > (SIZE_MAX - digit) / 10) {
                return false;
            }
            value = value * 10 + digit;
        } while (*p >= '0' && *p <= '9');
        return true;
    };
    for (;;) {
        skip_space();
        size_t start = 0, end = 0;
        if (*p == '-') {
            ++p;
            if (!number(end)) {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }
            start = end < file_size ? file_size - end : 0;
            end = file_size;
        } else {
            if (!number(start)) {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }
            skip_space();
            if (*p != '-') {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }
            ++p;
            skip_space();
            if (*p == ',' || *p == '\0') {
                end = file_size;
            } else if (!number(end) || start > end) {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            } else {
                end = end >= file_size ? file_size : end + 1;
            }
        }
        skip_space();
        if (*p != ',' && *p != '\0') {
            status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
            return;
        }
        if (++range_count > max_ranges) {
            excessive = true;
        }
        if (start < end) {
            if (end - start > file_size - selected_bytes) {
                excessive = true;
            } else {
                selected_bytes += end - start;
            }
            task_t task{};
            task.offset = start;
            task.length = end - start;
            if (!excessive) {
                ranges.push_back(task);
            }
        }
        if (!*p) {
            break;
        }
        ++p;
    }
    if (excessive) {
        full_response();
        return;
    }
    if (ranges.empty()) {
        status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
        return;
    }

    size_t length = 0;
    if (ranges.size() == 1) {
        length = ranges.front().length;
    } else {
        for (auto &task : ranges) {
            const int n = snprintf(task.part_header,
                                   sizeof(task.part_header),
                                   "%s--%s\r\nContent-Type: %s\r\n"
                                   "Content-Range: bytes %zu-%zu/%zu\r\n\r\n",
                                   &task == &ranges.front() ? "" : "\r\n",
                                   get_boundary().c_str(),
                                   get_mimetype().c_str(),
                                   static_cast<size_t>(task.offset),
                                   static_cast<size_t>(task.offset) + task.length - 1,
                                   file_size);
            if (n < 0 || static_cast<size_t>(n) >= sizeof(task.part_header) ||
                task.length > SIZE_MAX - static_cast<size_t>(n) ||
                length > SIZE_MAX - task.length - static_cast<size_t>(n)) {
                status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
                return;
            }
            length += task.length + n;
        }
        const std::string terminator = "\r\n--" + get_boundary() + "--\r\n";
        if (length > SIZE_MAX - terminator.length()) {
            status_code = SW_HTTP_RANGE_NOT_SATISFIABLE;
            return;
        }
        end_part = terminator;
        length += end_part.length();
    }
    tasks = std::move(ranges);
    content_length = length;
    status_code = SW_HTTP_PARTIAL_CONTENT;
}

}  // namespace http_server

void Server::add_rewrite_rule(const std::string &pattern, const std::string &replacement) {
    http_server::RewriteRule rule;
    rule.replacement = replacement;

    if (pattern.length() >= 2 && pattern.at(0) == '~' && pattern.at(pattern.length() - 1) == '~') {
        try {
            rule.regex = std::make_unique<std::regex>(pattern.substr(1, pattern.length() - 2));
        } catch (const std::regex_error &) {
            // Invalid expressions have always been ignored; reject them once at registration.
            return;
        }
    } else {
        rule.pattern = pattern;
    }

    if (rewrite_rules == nullptr) {
        rewrite_rules = std::make_shared<std::vector<http_server::RewriteRule>>();
    }
    rewrite_rules->emplace_back(std::move(rule));
}

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

bool Server::select_static_handler(const http_server::Request *request, const Connection *conn) {
    // Static responses run on the owning reactor. Other methods retain application
    // handling, including OPTIONS/CORS, rather than bypassing PHP with file content.
    if (request->method != SW_HTTP_GET && request->method != SW_HTTP_HEAD) {
        return false;
    }
    http_server::StaticHandler handler(this, request->buffer_->str + request->url_offset_, request->url_length_);
    if (!handler.try_serve()) {
        return false;
    }
    const auto redirect = handler.status_code == SW_HTTP_OK ? handler.get_directory_redirect() : std::string{};
    if (handler.status_code == SW_HTTP_OK && (!handler.try_serve_index_file() || !handler.open_file())) {
        return false;
    }

    const bool head = request->method == SW_HTTP_HEAD;
    SendData response{};
    response.info.fd = conn->session_id;
    bool failed = false;
    const auto send = [&](const char *data, size_t length) {
        if (failed || length == 0) {
            return;
        }
        response.info.type = SW_SERVER_EVENT_SEND_DATA;
        response.info.len = length;
        response.data = data;
        failed = send_to_connection(&response) < 0;
    };
    const auto complete = [&]() {
        // All static branches honor connection policy, including 304/404/autoindex.
        // A partial response cannot safely be reused after a send failure.
        if (failed || !request->keep_alive) {
            response.info.type = SW_SERVER_EVENT_CLOSE;
            response.info.ext_flags = failed ? CLOSE_RESET : 0;
            response.info.len = 0;
            response.data = nullptr;
            send_to_connection(&response);
        }
        return true;
    };
    const auto send_header = [&](int status, size_t length, const std::string &type, const std::string &extra) {
        String header(1024);
        header.append_format("HTTP/1.1 %s\r\nConnection: %s\r\nDate: %s\r\nServer: %s\r\n",
                             http_server::get_status_message(status),
                             request->keep_alive ? "keep-alive" : "close",
                             handler.get_date().c_str(),
                             SW_HTTP_SERVER_SOFTWARE);
        if (status != SW_HTTP_NOT_MODIFIED) {
            header.append_format("Content-Length: %zu\r\nContent-Type: %s\r\n", length, type.c_str());
        }
        if (status != SW_HTTP_NOT_FOUND && status != SW_HTTP_BAD_REQUEST) {
            header.append_format("Last-Modified: %s\r\n", handler.get_date_last_modified().c_str());
        }
        if (status == SW_HTTP_OK || status == SW_HTTP_PARTIAL_CONTENT || status == SW_HTTP_NOT_MODIFIED ||
            status == SW_HTTP_PRECONDITION_FAILED || status == SW_HTTP_RANGE_NOT_SATISFIABLE) {
            header.append_format("ETag: %s\r\n", handler.get_etag().c_str());
        }
        header.append(extra);
        header.append(SW_STRL("\r\n"));
        send(header.str, header.length);
    };

    if (handler.status_code == SW_HTTP_NOT_FOUND || handler.status_code == SW_HTTP_BAD_REQUEST) {
        const bool not_found = handler.status_code == SW_HTTP_NOT_FOUND;
        send_header(handler.status_code, not_found ? sizeof(SW_HTTP_PAGE_404) - 1 : 0, "text/html", "");
        if (!head && not_found) {
            send(SW_STRL(SW_HTTP_PAGE_404));
        }
        return complete();
    }
    if (!redirect.empty()) {
        send_header(SW_HTTP_MOVED_PERMANENTLY, 0, "text/html", "Location: " + redirect + "\r\n");
        return complete();
    }
    const int condition = handler.evaluate_preconditions(request->get_header("If-Match"),
                                                         request->get_header("If-Unmodified-Since"),
                                                         request->get_header("If-None-Match"),
                                                         request->get_header("If-Modified-Since"));
    if (condition != SW_HTTP_OK) {
        send_header(condition, 0, "text/html", "");
        return complete();
    }
    if (!handler.has_index_file() && handler.is_enabled_auto_index() && handler.is_dir()) {
        String body(1024);
        handler.make_index_page(&body);
        send_header(SW_HTTP_OK, body.length, "text/html", "");
        if (!head) {
            send(body.str, body.length);
        }
        return complete();
    }

    handler.parse_range(request->get_header("Range").c_str(), request->get_header("If-Range").c_str());
    const auto &tasks = handler.get_tasks();
    std::string extra;
    if (handler.status_code == SW_HTTP_RANGE_NOT_SATISFIABLE) {
        extra = "Content-Range: bytes */" + std::to_string(handler.get_filesize()) + "\r\n";
    } else if (handler.status_code == SW_HTTP_PARTIAL_CONTENT && tasks.size() == 1) {
        extra = "Content-Range: bytes " + std::to_string(tasks[0].offset) + "-" +
                std::to_string(tasks[0].offset + tasks[0].length - 1) + "/" + std::to_string(handler.get_filesize()) +
                "\r\n";
    } else if (handler.status_code == SW_HTTP_OK) {
        extra = "Accept-Ranges: bytes\r\n";
    }
    // Socket::handle_sendfile owns cork/uncork for large transfers. Pre-corking
    // here prevents it from claiming that state and can leave small/HEAD replies corked.
    send_header(handler.status_code, handler.get_content_length(), handler.get_content_type(), extra);
    if (!head && !failed && !tasks.empty()) {
        // The explicit opened-file argument stays inside this reactor call; no
        // filename or smart pointer is copied into a process/worker IPC packet.
        network::SendfileTask task{};
        for (const auto &part : tasks) {
            if (tasks.size() > 1) {
                send(part.part_header, strlen(part.part_header));
            }
            if (failed || part.length == 0) {
                break;
            }
            task.offset = part.offset;
            task.length = part.length;
            response.info.type = SW_SERVER_EVENT_SEND_FILE;
            response.info.len = sizeof(task);
            response.data = reinterpret_cast<char *>(&task);
            failed = send_to_connection(&response, &handler.get_file()) < 0;
        }
        if (tasks.size() > 1) {
            send(handler.get_end_part().c_str(), handler.get_end_part().length());
        }
    }
    return complete();
}

bool Server::apply_rewrite_rules(http_server::StaticHandler *handler) {
    if (!rewrite_rules || rewrite_rules->empty()) {
        return false;
    }

    bool rewritten = false;
    const auto &current_url = handler->get_request_url();

    for (const auto &rule : *rewrite_rules) {
        if (rule.regex) {
            try {
                if (std::regex_search(current_url, *rule.regex)) {
                    auto rewritten_url = std::regex_replace(current_url, *rule.regex, rule.replacement);
                    if (rewritten_url != current_url) {
                        handler->set_request_url(rewritten_url);
                        rewritten = true;
                        break;
                    }
                }
            } catch (const std::regex_error &e) {
                continue;
            }
        } else {
            if (starts_with(current_url, rule.pattern)) {
                std::string rewritten_url = rule.replacement + current_url.substr(rule.pattern.length());
                handler->set_request_url(rewritten_url);
                rewritten = true;
                break;
            }
        }
    }

    return rewritten;
}
}  // namespace swoole
