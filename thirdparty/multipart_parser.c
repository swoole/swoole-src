/* Based on node-formidable by Felix Geisendörfer
 * Igor Afonov - afonov@gmail.com - 2012
 * MIT License - http://www.opensource.org/licenses/mit-license.php
 */

#include "multipart_parser.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef DEBUG_MULTIPART
#include <ctype.h>
#define multipart_log(format, ...)                                                                                     \
    do {                                                                                                               \
        fprintf(stderr, "[MULTIPART_PARSER] line %d: " format "\n", __LINE__, __VA_ARGS__);                            \
    } while (0)
#define multipart_log_c(format)                                                                                        \
    do {                                                                                                               \
        if (isprint(c)) {                                                                                              \
            multipart_log("parsing '%c' " format, c);                                                                  \
        } else {                                                                                                       \
            multipart_log("parsing '\\x%0.2x' " format, c);                                                            \
        }                                                                                                              \
    } while (0)
#else
#define multipart_log(format, ...)
#define multipart_log_c(format, ...)
#endif

#define NOTIFY_CB(FOR, r)                                                                                              \
    do {                                                                                                               \
        if (p->settings->on_##FOR) {                                                                                   \
            if ((ret = p->settings->on_##FOR(p)) == MPPE_PAUSED) {                                                     \
                return r;                                                                                              \
            } else if (ret != MPPE_OK) {                                                                               \
                return MPPE_ERROR;                                                                                     \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define EMIT_DATA_CB(FOR, r, ptr, len)                                                                                 \
    do {                                                                                                               \
        if (p->settings->on_##FOR) {                                                                                   \
            if ((ret = p->settings->on_##FOR(p, ptr, len)) == MPPE_PAUSED) {                                           \
                return r;                                                                                              \
            } else if (ret != MPPE_OK) {                                                                               \
                return MPPE_ERROR;                                                                                     \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define ERROR_OUT(reason)                                                                                              \
    do {                                                                                                               \
        p->error_unexpected = c;                                                                                       \
        p->error_i = i;                                                                                                \
        p->error_reason = reason;                                                                                      \
        return MPPE_ERROR;                                                                                             \
    } while (0)

#define ERROR_EXPECT(reason, ch)                                                                                       \
    do {                                                                                                               \
        p->error_expected = ch;                                                                                        \
        if (ch == LF) {                                                                                                \
            multipart_log("expecting LF at %zu, but it's \\x%.2x", i, c);                                              \
        } else if (ch == CR) {                                                                                         \
            multipart_log("expecting CR at %zu, but it's \\x%.2x", i, c);                                              \
        } else {                                                                                                       \
            multipart_log("expecting '%c' at %zu, but it's \\x%.2x", ch, i, c);                                        \
        }                                                                                                              \
        ERROR_OUT(reason);                                                                                             \
    } while (0)

#define LF 10
#define CR 13

enum state {
    s_uninitialized = 1,
    s_start,
    s_start_boundary,
    s_header_field_start,
    s_header_field,
    s_headers_almost_done,
    s_header_value_start,
    s_header_value,
    s_header_value_almost_done,
    s_part_data_start,
    s_part_data,
    s_part_data_almost_boundary,
    s_part_data_boundary,
    s_part_data_almost_almost_end,
    s_part_data_almost_end,
    s_part_data_end,
    s_part_data_final_hyphen,
    s_end
};

multipart_parser *multipart_parser_init(const char *boundary,
                                        size_t boundary_length,
                                        const multipart_parser_settings *settings) {
    multipart_parser *p = calloc(sizeof(multipart_parser) + boundary_length + boundary_length + 9 + 4, sizeof(char));
    memcpy(p->multipart_boundary, "--", 2);
    memcpy(p->multipart_boundary + 2, boundary, boundary_length);
    p->multipart_boundary[2 + boundary_length] = 0;

    p->boundary_length = boundary_length + 2;
    p->index = 0;
    p->state = s_start;
    p->error_i = 0;
    p->error_unexpected = 0;
    p->error_expected = 0;
    p->error_reason = MPPE_OK;
    p->state = s_start;
    p->settings = settings;

    return p;
}

void multipart_parser_free(multipart_parser *p) {
    free(p);
}

int multipart_parser_error_msg(multipart_parser *p, char *buf, size_t len) {
    int ret;
    switch (p->error_reason) {
    case MPPE_OK:
        return 0;
    case MPPE_PAUSED:
        return snprintf(buf, len, "parser paused");
    case MPPE_UNKNOWN:
    default:
        abort();
        return 0;
    case MPPE_BOUNDARY_END_NO_CRLF:
        ret = snprintf(buf, len, "no CRLF at first boundary end: ");
        break;
    case MPPE_BAD_START_BOUNDARY:
        ret = snprintf(buf, len, "first boundary mismatching: ");
        break;
    case MPPE_INVALID_HEADER_FIELD_CHAR:
        ret = snprintf(buf, len, "invalid char in header field: ");
        break;
    case MPPE_INVALID_HEADER_VALUE_CHAR:
        ret = snprintf(buf, len, "invalid char in header value: ");
        break;
    case MPPE_BAD_PART_END:
        ret = snprintf(buf, len, "no next part or final hyphen: expecting CR or '-' ");
        break;
    case MPPE_END_BOUNDARY_NO_DASH:
        ret = snprintf(buf, len, "bad final hyphen: ");
        break;
    }
    if (ret < 0) {
        return 0;
    }
    if ((size_t) ret >= len) {
        return ret;
    }
    switch (p->error_expected) {
    case '\0':
        break;
    case CR:
        ret += snprintf(buf + ret, len - ret, "expecting CR ");
        break;
    case LF:
        ret += snprintf(buf + ret, len - ret, "expecting LF ");
        break;
    default:
        ret += snprintf(buf + ret, len - ret, "expecting '%c' ", p->error_expected);
        break;
    }
    if (ret < 0) {
        return 0;
    }
    if ((size_t) ret >= len) {
        return ret;
    }
    if (isprint(p->error_unexpected)) {
        ret += snprintf(buf + ret, len - ret, "at %zu, but it is '%c'", p->error_i, p->error_unexpected);
    } else {
        ret += snprintf(buf + ret, len - ret, "at %zu, but it is '\\x%.2x'", p->error_i, p->error_unexpected);
    }
    return ret;
}

ssize_t multipart_parser_execute(multipart_parser *p, const char *buf, size_t len) {
    size_t i = 0;
    size_t mark = 0;
    size_t mark_end = 0;
    char c, cl;
    int is_last = 0;
    int ret;

    while (i < len) {
        c = buf[i];
        is_last = (i == (len - 1));
        switch (p->state) {
        case s_start:
            multipart_log_c("s_start");
            p->index = 0;
            p->state = s_start_boundary;
            /* fallthrough */
        case s_start_boundary:
            multipart_log_c("s_start_boundary");
            if (p->index == p->boundary_length) {
                if (c != CR) {
                    ERROR_EXPECT(MPPE_BOUNDARY_END_NO_CRLF, CR);
                }
                p->index++;
                break;
            } else if (p->index == (size_t)(p->boundary_length + 1)) {
                if (c != LF) {
                    ERROR_EXPECT(MPPE_BOUNDARY_END_NO_CRLF, LF);
                }
                p->index = 0;
                p->state = s_header_field_start;
                NOTIFY_CB(part_data_begin, i + 1);
                break;
            }
            if (c != p->multipart_boundary[p->index]) {
                ERROR_EXPECT(MPPE_BAD_START_BOUNDARY, p->multipart_boundary[p->index]);
            }
            p->index++;
            break;
        case s_header_field_start:
            multipart_log_c("s_header_field_start");
            mark = i;
            p->state = s_header_field;
            /* fallthrough */
        case s_header_field:
            multipart_log_c("s_header_field");
            if (c == CR) {
                p->state = s_headers_almost_done;
                break;
            }
            if (c == '-') {
                if (is_last) {
                    EMIT_DATA_CB(header_field, i + 1, buf + mark, i - mark + 1);
                }
                break;
            }
            if (c == ':') {
                p->state = s_header_value_start;
                EMIT_DATA_CB(header_field, i + 1, buf + mark, i - mark);
                break;
            }
            cl = c | 0x20;
            if (cl < 'a' || cl > 'z') {
                multipart_log_c("invalid character in header field");
                p->error_unexpected = c;
                ERROR_OUT(MPPE_INVALID_HEADER_FIELD_CHAR);
            }
            if (is_last) {
                EMIT_DATA_CB(header_field, i + 1, buf + mark, i - mark + 1);
            }
            break;
        case s_headers_almost_done:
            multipart_log_c("s_headers_almost_done");
            if (c != LF) {
                ERROR_EXPECT(MPPE_INVALID_HEADER_VALUE_CHAR, LF);
            }
            p->state = s_part_data_start;
            break;
        case s_header_value_start:
            multipart_log_c("s_header_value_start");
            if (c == ' ') {
                break;
            }
            mark = i;
            p->state = s_header_value;
            /* fallthrough */
        case s_header_value:
            multipart_log_c("s_header_value");
            if (c == CR) {
                p->state = s_header_value_almost_done;
                EMIT_DATA_CB(header_value, i + 1, buf + mark, i - mark);
            }
            if (is_last) {
                EMIT_DATA_CB(header_value, i + 1, buf + mark, i - mark + 1);
            }
            break;
        case s_header_value_almost_done:
            multipart_log_c("s_header_value_almost_done");
            if (c != LF) {
                ERROR_EXPECT(MPPE_INVALID_HEADER_VALUE_CHAR, LF);
            }
            p->state = s_header_field_start;
            break;
        case s_part_data_start:
            multipart_log_c("s_part_data_start");
            mark = i;
            p->state = s_part_data;
            NOTIFY_CB(headers_complete, i);
            /* fallthrough */
        case s_part_data:
        data_rollback:
            multipart_log_c("s_part_data");
            mark_end = i + 1;
            if (c == CR) {
                mark_end--;
                if (is_last) {
                    if (i > 1) {
                        EMIT_DATA_CB(part_data, i, buf + mark, mark_end - mark);
                    } else {
                        // donot trig callback
                        return 0;
                    }
                }
                p->state = s_part_data_almost_boundary;
                break;
            }
            if (is_last) {
                EMIT_DATA_CB(part_data, i + 1, buf + mark, mark_end - mark);
            }
            break;
        case s_part_data_almost_boundary:
            multipart_log_c("s_part_data_almost_boundary");
            if (c == LF) {
                if (is_last) {
                    if (i > 2) {
                        EMIT_DATA_CB(part_data, mark_end, buf + mark, mark_end - mark);
                    } else {
                        // donot trig callback
                        return 0;
                    }
                }
                p->state = s_part_data_boundary;
                p->index = 0;
                break;
            }
            p->state = s_part_data;
            goto data_rollback;
        case s_part_data_boundary:
            multipart_log_c("s_part_data_boundary");
            if (p->multipart_boundary[p->index] != c) {
                p->state = s_part_data;
                goto data_rollback;
            }
            if (is_last) {
                if (i > p->index + 2) {
                    EMIT_DATA_CB(part_data, i - p->index - 2, buf + mark, mark_end - mark);
                } else {
                    // donot trig callback
                    return 0;
                }
            }
            if ((++p->index) == p->boundary_length) {
                p->state = s_part_data_almost_almost_end;
                EMIT_DATA_CB(part_data, i + 1, buf + mark, i + 1 - p->boundary_length - 2 - mark);
            }
            break;
        case s_part_data_almost_almost_end:
            multipart_log_c("s_part_data_almost_almost_end");
            p->state = s_part_data_almost_end;
            NOTIFY_CB(part_data_end, i);
            /* fallthrough */
        case s_part_data_almost_end:
            multipart_log_c("s_part_data_almost_end");
            if (c == '-') {
                p->state = s_part_data_final_hyphen;
                break;
            }
            if (c == CR) {
                p->state = s_part_data_end;
                break;
            }
            // should be end or another part
            multipart_log("expecting '-' or CR at %zu but it's \\x%0.2x", i, c);
            ERROR_OUT(MPPE_BAD_PART_END);
        case s_part_data_final_hyphen:
            multipart_log_c("s_part_data_final_hyphen");
            if (c == '-') {
                p->state = s_end;
                NOTIFY_CB(body_end, i);
                break;
            }
            // should be -
            ERROR_EXPECT(MPPE_END_BOUNDARY_NO_DASH, '-');
        case s_part_data_end:
            multipart_log_c("s_part_data_end");
            if (c == LF) {
                p->state = s_header_field_start;
                NOTIFY_CB(part_data_begin, i + 1);
                break;
            }
            // should be -
            ERROR_EXPECT(MPPE_END_BOUNDARY_NO_DASH, '-');
        case s_end:
            multipart_log_c("s_end");
            break;
        default:
            multipart_log_c("Multipart parser unrecoverable error");
            ERROR_OUT(MPPE_UNKNOWN);
        }
        ++i;
    }
    return i;
}
