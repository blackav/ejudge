#! /bin/bash

if head -1 ~/user-data.sh | grep "/bin/bash"
then
    . ~/user-data.sh
else
    rm -f ~/user-data.sh
fi

if [ "$EJ_MOUNT_HOST" = "" ]
then
    echo "EJ_MOUNT_HOST is not set" >& 2
    exit 1
fi

sshfs ${EJ_MOUNT_HOST}:/home/judges /home/judges -o ServerAliveInterval=30,reconnect

mkdir -p /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runmono /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runjava /var/lib/ejudge/scripts
cd /home/judges
exec screen -d -m /home/ejudge/2start-super-run.sh
