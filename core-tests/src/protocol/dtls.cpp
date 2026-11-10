#include "test_core.h"
#include "swoole_dtls.h"
#include "swoole_util.h"

#include <atomic>

using namespace swoole;

#ifdef SW_SUPPORT_DTLS
TEST(DTLSMethods, ssl_initialization_publishes_one_immutable_method_table) {
    const bool already_initialized = dtls::BIO_get_methods() != nullptr;
    ON_SCOPE_EXIT {
        if (!already_initialized) {
            swoole_ssl_destroy();
        }
    };
    swoole_ssl_init();
    auto *methods = dtls::BIO_get_methods();
    ASSERT_NE(methods, nullptr);
    swoole_ssl_init();
    EXPECT_EQ(dtls::BIO_get_methods(), methods);

    std::atomic<size_t> failures{0};
    std::vector<std::thread> readers;
    for (size_t i = 0; i < 8; i++) {
        readers.emplace_back([&]() {
            for (size_t n = 0; n < 64; n++) {
                auto *shared_methods = dtls::BIO_get_methods();
                if (shared_methods != methods) {
                    failures++;
                }
                BIO *bio = BIO_new(shared_methods);
                if (!bio) {
                    failures++;
                }
                BIO_free(bio);
            }
        });
    }
    for (auto &reader : readers) {
        reader.join();
    }
    EXPECT_EQ(failures.load(), 0u);
}
#endif
