#! /bin/bash

set -ex

dnf -y update && dnf -y install mongo-c-driver-devel libbson-devel httpd httpd-devel httpd-tools net-tools wget tar bzip2 p7zip fuse-devel htop make gcc glibc-devel glibc-static bison flex gawk sed file zlib zlib-devel ncurses ncurses-devel expat expat-devel gettext gettext-devel libzip libzip-devel libcurl libcurl-devel libuuid libuuid-devel openssl openssl-devel git bc vim wget fuse-sshfs kernel-tools gcc strace valgrind gcc-c++ libstdc++-static python python3 nasm libstdc++-devel glibc-devel.i686 glibc-static.i686 libstdc++-devel.i686 libstdc++-static.i686 libtool autoconf automake clang clang-devel clang-libs python2 pypy pypy3 rust nodejs swift-lang mariadb-connector-c-devel mariadb-server-utils mariadb-common mariadb-errmsg glibc-locale-source golang gdb

dnf clean all

set +e

localedef -v -c -i ru_RU -f UTF-8 ru_RU.UTF-8

set -e

adduser -c 'ejudge user' -s /bin/bash ejudge
adduser -c 'ejudge executor' -d / -M -s /sbin/nologin ejexec
adduser -c 'ejudge compiler' -d /home/judges/compile -M -s /sbin/nologin ejcompile

#RELEASE=
RELEASE='RELEASE=1'

./configure --prefix=/opt/ejudge --enable-charset=utf-8 --with-httpd-cgi-bin-dir=/var/www/cgi-bin --with-httpd-htdocs-dir=/var/www/html --enable-ajax --enable-local-dir=/var/lib/ejudge --enable-hidden-server-bins --with-primary-user=ejudge --with-exec-user=ejexec --with-compile-user=ejcompile --enable-compile-spool-dir --enable-run-spool-dir --enable-contests-status-dir && ulimit -n 65536 && make ${RELEASE} && make ${RELEASE} install && /opt/ejudge/bin/ejudge-suid-setup && /opt/ejudge/bin/ejudge-upgrade-web

> ejudge-install.sh
chmod 755 ejudge-install.sh
chown ejudge:ejudge ejudge-install.sh
./ejudge-setup -u ejudge -g ejudge -b -B
cp -p ejudge-install.sh /opt/ejudge/bin
