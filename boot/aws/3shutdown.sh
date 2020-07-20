#! /bin/bash
fusermount -u /home/judges
rm -rf /tmp/ejudge/super-run
rm -rf /var/lib/ejudge/*
exec ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa_shutdown fedora@localhost "sudo /sbin/shutdown now"
