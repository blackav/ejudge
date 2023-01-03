#! /bin/bash

 # mkdir /opt/ejudge
 # chown user:user /opt/ejudge

if [ ! -d /home/judges ]
then
    mkdir -p /home/judges
    chown ejudge:ejudge /home/judges
fi

if [ ! -d /home/ej-compile-spool ]
then
    mkdir -p /home/ej-compile-spool
    chown ejudge:ejudge /home/ej-compile-spool
    chmod 755 /home/ej-compile-spool
fi

if [ ! -d /home/ej-run-spool ]
then
    mkdir -p /home/ej-run-spool
    chown ejudge:ejudge /home/ej-run-spool
    chmod 755 /home/ej-run-spool
fi

if [ ! -d /var/lib/ejudge ]
then
    mkdir -p /var/lib/ejudge
    chown ejudge:ejudge /var/lib/ejudge
fi

if [ ! -d /var/log/ejudge ]
then
    mkdir /var/log/ejudge
    chown ejudge:ejudge /var/log/ejudge
fi

/usr/sbin/httpd -DFOREGROUND
