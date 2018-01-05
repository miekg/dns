#!/usr/bin/env bash
set -xeuo pipefail
if [ $# -ne 1 ]; then
    echo "supply target dir"
    exit 1
fi
TARGET_DIR=$1
BIND_URL="https://ftp.isc.org/isc/bind9/9.12.0rc1/bind-9.12.0rc1.tar.gz"
OPENSSL_URL="https://codeload.github.com/openssl/openssl/zip/master"
OPENSSL_ARCHIVE="openssl.zip"
BIND_ARCHIVE="bind.tar.gz"
TEMP_DIR=$(mktemp -d)
cd "${TEMP_DIR}"
mkdir -p archives src/openssl-master src/bind openssl-install
curl -4 \
    "${OPENSSL_URL}" -o "archives/${OPENSSL_ARCHIVE}" \
    "${BIND_URL}" -o "archives/${BIND_ARCHIVE}"
unzip -qod src "archives/${OPENSSL_ARCHIVE}"
tar -C src/bind --strip-components=1 -xf "archives/${BIND_ARCHIVE}"
cd "${TEMP_DIR}/src/openssl-master"
OPENSSL_INSTALL_DIR="${TEMP_DIR}/openssl-install"
./config --prefix="${OPENSSL_INSTALL_DIR}" --openssldir="${OPENSSL_INSTALL_DIR}"
make
make install_sw
cd "${TEMP_DIR}/src/bind"
export LD_LIBRARY_PATH="${OPENSSL_INSTALL_DIR}/lib"
./configure \
    --prefix="${TARGET_DIR}" \
    --with-openssl="${OPENSSL_INSTALL_DIR}" \
    --with-ecdsa \
    --with-eddsa \
    --with-libxml2=no
for path in ${TEMP_DIR}/openssl-install/lib/*.a; do
    lib=$(basename -s .a ${path})
    lib=${lib#lib}
    find . -type f -name "Makefile" | while read f; do
        sed -i=bak -e "s|-l${lib}|${path}|g" "${f}"
    done
done
make
make install
