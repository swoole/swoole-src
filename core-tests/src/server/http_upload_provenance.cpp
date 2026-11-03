#include "test_core.h"
#include "swoole_http.h"
#include "swoole_server.h"

#include <algorithm>
#include <cctype>

using namespace swoole;

namespace {
struct MultipartFixture {
    Server server{Server::MODE_BASE};
    String buffer{SW_BUFFER_SIZE_BIG};
    http_server::Request request;

    MultipartFixture() {
        server.upload_tmp_dir = "/tmp";
        server.upload_max_filesize = 1024 * 1024;
        request.buffer_ = &buffer;
        request.max_length_ = SW_BUFFER_SIZE_BIG;
        request.form_data_ = new http_server::FormData{};
        request.form_data_->multipart_boundary_buf = "boundary=b";
        request.form_data_->multipart_boundary_len = strlen("boundary=b");
        EXPECT_TRUE(request.init_multipart_parser(&server));
    }

    // Like the reactor, the parse buffer is cleared after every read and refilled from its start.
    bool feed(const std::string &data) {
        request.buffer_->append(data.data(), data.length());
        return request.parse_multipart_data(request.buffer_);
    }

    std::string forwarded() {
        auto result = request.form_data_->multipart_buffer_->to_std_string();
        std::transform(
            result.begin(), result.end(), result.begin(), [](unsigned char c) { return std::tolower(c); });
        return result;
    }
};
}  // namespace

static const char *kPartPrefix = "--b\r\nContent-Disposition: form-data; name=\"text\"\r\n";

TEST(http_server, reject_client_upload_marker) {
    for (const auto &name : {"Swoole-Upload-File", "sWoOlE-uPlOaD-fIlE"}) {
        const std::string body = std::string(kPartPrefix) + name + ": /tmp/victim\r\n\r\nvalue\r\n--b--\r\n";
        for (size_t split = 1; split < body.length(); split++) {
            SCOPED_TRACE(std::string(name) + " split=" + std::to_string(split));
            MultipartFixture f;
            bool ok = f.feed(body.substr(0, split));
            if (ok) {
                ok = f.feed(body.substr(split));
            }
            EXPECT_FALSE(ok);
            EXPECT_EQ(f.forwarded().find("\r\nswoole-upload-file:"), std::string::npos);
            EXPECT_FALSE(f.request.tried_to_dispatch);
        }
    }
}

TEST(http_server, header_name_split_across_reads_is_assembled) {
    const std::string body = std::string(kPartPrefix) + "X-Custom-Header: v\r\n\r\nvalue\r\n--b--\r\n";
    const size_t start = body.find("X-Custom-Header");
    for (size_t split = start; split <= start + strlen("X-Custom-Header: "); split++) {
        SCOPED_TRACE(split);
        MultipartFixture f;
        ASSERT_TRUE(f.feed(body.substr(0, split)));
        ASSERT_TRUE(f.feed(body.substr(split)));
        EXPECT_TRUE(f.request.tried_to_dispatch);
        EXPECT_NE(f.forwarded().find("\r\nx-custom-header: v\r\n"), std::string::npos);
    }
}

// The header name must not be a reference into the read buffer: a later read overwrites that memory.
TEST(http_server, overwritten_read_buffer_cannot_forge_upload_marker) {
    const std::string name(24, 'A');
    const std::string first = std::string(kPartPrefix) + name + ":";
    const size_t name_offset = first.length() - name.length() - 1;

    // The forged header has the same length as the already accepted name and lands exactly where it was stored.
    const std::string forged = "A: b\r\nSwoole-Upload-File";
    ASSERT_EQ(forged.length(), name.length());
    std::string second = " /tmp/victim\r\n\r\n";
    ASSERT_LE(second.length(), name_offset);
    second.append(name_offset - second.length(), 'x');
    second += forged + "\r\n--b--\r\n";

    MultipartFixture f;
    ASSERT_TRUE(f.feed(first));
    ASSERT_TRUE(f.feed(second));
    EXPECT_EQ(f.forwarded().find("\r\nswoole-upload-file:"), std::string::npos);
}
