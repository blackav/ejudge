#! /bin/bash

set -x

localedef -v -c -i ru_RU -f UTF-8 ru_RU.UTF-8

set -e

adduser -c 'ejudge user' -s /bin/bash ejudge
adduser -c 'ejudge executor' -d / -M -s /sbin/nologin ejexec
adduser -c 'ejudge compiler' -d /home/judges/compile -M -s /sbin/nologin ejcompile

#RELEASE=
RELEASE='RELEASE=1'

rm -rf .git
./configure --prefix=/opt/ejudge --enable-charset=utf-8 --with-httpd-cgi-bin-dir=/var/www/cgi-bin --with-httpd-htdocs-dir=/var/www/html --enable-ajax --enable-local-dir=/var/lib/ejudge --enable-hidden-server-bins --with-primary-user=ejudge --with-exec-user=ejexec --with-compile-user=ejcompile --enable-compile-spool-dir --enable-run-spool-dir --enable-contests-status-dir && ulimit -n 65536 && make ${RELEASE} && make ${RELEASE} install && /opt/ejudge/bin/ejudge-suid-setup && /opt/ejudge/bin/ejudge-upgrade-web

> ejudge-install.sh
chmod 755 ejudge-install.sh
chown ejudge:ejudge ejudge-install.sh
./ejudge-setup -u ejudge -g ejudge -b -B
cp -p ejudge-install.sh /opt/ejudge/bin
cp docker/httpd.conf /etc/httpd/conf

wget https://ejudge.ru/download/ejudge-container-fedora-36.tbz
mv ejudge-container-fedora-36.tbz /opt/ejudge/share/ejudge
( cd /opt/ejudge/share/ejudge ; tar xf ejudge-container-fedora-36.tbz )
rm /opt/ejudge/share/ejudge/ejudge-container-fedora-36.tbz
cp -p /etc/passwd /opt/ejudge/share/ejudge/container/etc
cp -p /etc/group /opt/ejudge/share/ejudge/container/etc
