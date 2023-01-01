FROM fedora:36 AS builder

WORKDIR /app
COPY . /app

RUN ulimit -a

RUN dnf -y update && dnf -y install libbson-devel httpd httpd-devel httpd-tools net-tools wget tar bzip2 p7zip fuse-devel openvpn htop make gcc glibc-devel glibc-static bison flex gawk sed file zlib zlib-devel ncurses ncurses-devel expat expat-devel gettext gettext-devel libzip libzip-devel libcurl libcurl-devel libuuid libuuid-devel openssl openssl-devel git tmux bc vim screen wget ncftp mc fuse-sshfs patch kernel-tools kernel-devel gcc strace subversion gdb valgrind gcc-c++ libstdc++-static python python3 gcc-gfortran libgfortran-static gcc-go libgo-static nasm libstdc++-devel glibc-devel.i686 glibc-static.i686 libstdc++-devel.i686 libstdc++-static.i686 libtool autoconf automake clang clang-devel clang-libs php python2 pypy pypy3 ruby rust scala nodejs swift-lang libnfs libnfs-utils libnfsidmap nfs-stats-utils nfs-utils nfswatch  nfs4-acl-tools golang

RUN ./configure --prefix=/opt/ejudge --enable-charset=utf-8 --with-httpd-cgi-bin-dir=/var/www/cgi-bin --with-httpd-htdocs-dir=/var/www/html --enable-ajax --enable-local-dir=/var/lib/ejudge --enable-hidden-server-bins --with-primary-user=ejudge --with-exec-user=ejexec --with-compile-user=ejcompile --enable-compile-spool-dir --enable-run-spool-dir --enable-contests-status-dir && ulimit -n 65536 && make && make install
