ARG BASE_IMAGE=debian:bookworm-slim

FROM ${BASE_IMAGE}
ARG SSL_VERSION=3.2.1
ENV SRC_DIR=/tmp/openssl-src
ENV OUT_DIR=/usr/local/.openssl
RUN chmod 1777 /tmp
RUN <<`
    set -e
    apt-get update
    apt-get install -y curl build-essential libssl-dev libz-dev
    apt-get remove -y openssl
    apt-get clean
`
WORKDIR ${SRC_DIR}
RUN <<`
    set -ex
    curl --silent --location -O https://github.com/openssl/openssl/releases/download/openssl-${SSL_VERSION}/openssl-${SSL_VERSION}.tar.gz
    tar -xf openssl-${SSL_VERSION}.tar.gz --strip-components=1
`
RUN ./config --prefix=${OUT_DIR} --openssldir=${OUT_DIR} shared zlib
RUN <<`
    set -e
    make
    make test
    make install
`
RUN <<`
    set -e
    echo "${OUT_DIR}/lib" > /etc/ld.so.conf.d/openssl-${SSL_VERSION}.conf
    ldconfig

    ln -sf ${OUT_DIR}/bin/openssl /usr/bin/openssl
    
    # Handle both lib and lib64 directory structures
    if [ -d "${OUT_DIR}/lib64" ]; then
        LIB_DIR="${OUT_DIR}/lib64"
    else
        LIB_DIR="${OUT_DIR}/lib"
    fi
    
    # Handle different system library directory structures
    SYSTEM_LIB_DIR="/lib"
    if [ -d "/lib/$(uname -m)-linux-gnu" ]; then
        SYSTEM_LIB_DIR="/lib/$(uname -m)-linux-gnu"
    elif [ -d "/lib64" ]; then
        SYSTEM_LIB_DIR="/lib64"
    fi
    
    ln -sf ${LIB_DIR}/libssl.so.3 ${SYSTEM_LIB_DIR}/libssl.so.3
    ln -sf ${LIB_DIR}/libcrypto.so.3 ${SYSTEM_LIB_DIR}/libcrypto.so.3
`
WORKDIR /
RUN rm -rf ${SRC_DIR}