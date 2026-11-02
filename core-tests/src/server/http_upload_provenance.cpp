#include "test_core.h"
#include "swoole_http.h"
#include "swoole_server.h"

#include <algorithm>
#include <cctype>

using namespace swoole;

TEST(http_server, discard_client_upload_marker) {
    Server server(Server::MODE_BASE);
    server.upload_tmp_dir = "/tmp";
    server.upload_max_filesize = 1024 * 1024;

    for (const auto &name : {"sWoOlE-uPlOaD-fIlE", "X-Swoole-Upload-File"}) {
        const std::string body = std::string("--b\r\nContent-Disposition: form-data; name=\"text\"\r\n") + name +
                                 ": not-a-server-upload\r\n\r\nvalue\r\n--b--\r\n";
        const size_t start = body.find(name);
        // A fragmented harmless name may end in the reserved name. Filter the exact name being forwarded.
        for (size_t split = start; split <= start + strlen(name); split++) {
            SCOPED_TRACE(split);
            String original(SW_BUFFER_SIZE_BIG);
            original.append(body.data(), split);
            http_server::Request request;
            request.buffer_ = &original;
            request.max_length_ = SW_BUFFER_SIZE_BIG;
            request.form_data_ = new http_server::FormData{};
            request.form_data_->multipart_boundary_buf = "boundary=b";
            request.form_data_->multipart_boundary_len = strlen("boundary=b");
            ASSERT_TRUE(request.init_multipart_parser(&server));
            ASSERT_TRUE(request.parse_multipart_data(request.buffer_));
            request.buffer_->append(body.data() + split, body.size() - split);
            ASSERT_TRUE(request.parse_multipart_data(request.buffer_));
            ASSERT_TRUE(request.tried_to_dispatch);
            auto forwarded = request.form_data_->multipart_buffer_->to_std_string();
            std::transform(
                forwarded.begin(), forwarded.end(), forwarded.begin(), [](unsigned char c) { return std::tolower(c); });
            EXPECT_EQ(forwarded.find("\r\nswoole-upload-file:"), std::string::npos);
            EXPECT_NE(forwarded.find("\r\n\r\nvalue\r\n"), std::string::npos);
        }
    }
}
