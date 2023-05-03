#! /bin/bash
/opt/ejudge/bin/ejudge-control -s stop
fusermount -u /home/judges
rm -rf /tmp/ejudge/super-run
rm -rf /var/lib/ejudge/*
exec ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i /home/ejudge/.ssh/id_reboot root@localhost "/sbin/reboot"
