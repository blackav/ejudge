#! /bin/bash

set -ex

dnf -y update && dnf -y install mongo-c-driver-devel libbson-devel httpd httpd-devel httpd-tools net-tools wget tar bzip2 p7zip fuse-devel openvpn htop make gcc glibc-devel glibc-static bison flex gawk sed file zlib zlib-devel ncurses ncurses-devel expat expat-devel gettext gettext-devel libzip libzip-devel libcurl libcurl-devel libuuid libuuid-devel openssl openssl-devel git tmux bc vim screen wget ncftp mc fuse-sshfs patch kernel-tools kernel-devel gcc strace subversion gdb valgrind gcc-c++ libstdc++-static python python3 gcc-gfortran libgfortran-static gcc-go libgo-static nasm libstdc++-devel glibc-devel.i686 glibc-static.i686 libstdc++-devel.i686 libstdc++-static.i686 libtool autoconf automake clang clang-devel clang-libs php python2 pypy pypy3 ruby rust scala nodejs swift-lang golang mariadb-connector-c-devel mariadb-server-utils mariadb-common mariadb-errmsg glibc-locale-source

localedef -v -c -i ru_RU -f UTF-8 ru_RU.UTF-8

adduser -c 'ejudge user' -s /bin/bash ejudge
adduser -c 'ejudge executor' -d / -M -s /sbin/nologin ejexec
adduser -c 'ejudge compiler' -d /home/judges/compile -M -s /sbin/nologin ejcompile

 # mkdir /opt/ejudge
 # chown user:user /opt/ejudge
 # mkdir /home/judges
 # chown ejudge:ejudge /home/judges
 # mkdir /home/ej-compile-spool
 # chown ejudge:ejcompile /home/ej-compile-spool
 # chmod 6775 /home/ej-compile-spool
 # mkdir /home/ej-run-spool
 # chown ejudge:ejudge /home/ej-run-spool
 # chmod 755 /home/ej-run-spool
 # mkdir /var/lib/ejudge
 # chown ejudge:ejudge /var/lib/ejudge
 # mkdir /var/log/ejudge
 # chown ejudge:ejudge /var/log/ejudge
 # cd /home/judges; ln -s /var/log/ejudge var

./configure --prefix=/opt/ejudge --enable-charset=utf-8 --with-httpd-cgi-bin-dir=/var/www/cgi-bin --with-httpd-htdocs-dir=/var/www/html --enable-ajax --enable-local-dir=/var/lib/ejudge --enable-hidden-server-bins --with-primary-user=ejudge --with-exec-user=ejexec --with-compile-user=ejcompile --enable-compile-spool-dir --enable-run-spool-dir --enable-contests-status-dir && ulimit -n 65536 && make RELEASE=1 && make RELEASE=1 install && /opt/ejudge/bin/ejudge-suid-setup && /opt/ejudge/bin/ejudge-upgrade-web
