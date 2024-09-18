FROM fedora:40 AS dependencies

RUN dnf -y update && dnf -y install mongo-c-driver-devel libbson-devel httpd httpd-devel httpd-tools net-tools wget tar bzip2 p7zip fuse-devel htop make gcc glibc-devel glibc-static bison flex gawk sed file zlib zlib-devel ncurses ncurses-devel expat expat-devel gettext gettext-devel libzip libzip-devel libcurl libcurl-devel libuuid libuuid-devel openssl openssl-devel git bc vim wget fuse-sshfs kernel-tools gcc strace valgrind gcc-c++ libstdc++-static python python3 nasm libstdc++-devel glibc-devel.i686 glibc-static.i686 libstdc++-devel.i686 libstdc++-static.i686 libtool autoconf automake clang clang-devel clang-libs python2 pypy pypy3 rust nodejs swift-lang mariadb-connector-c-devel mariadb-server-utils mariadb-common mariadb-errmsg glibc-locale-source golang gdb elfutils-libelf-devel procps hiredis-devel

RUN dnf clean all

FROM dependencies AS build

WORKDIR /app
COPY . /app

RUN /app/docker/build.sh

COPY docker/entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
