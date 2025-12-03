apt install -y cmake make gcc g++ \
    iputils-ping \
    libc-ares-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libmariadb-dev \
    libaio-dev libaio1  \
    zlib1g-dev \
    sqlite3 libsqlite3-dev \
    libbrotli-dev \
    libpq-dev \
    unixodbc-dev \
    firebird-dev \
    libzstd-dev \
    libssh2-1-dev

# The built-in liburing version of Ubuntu is 0.7, which is too low. We must install liburing through the source code
# liburing-dev
