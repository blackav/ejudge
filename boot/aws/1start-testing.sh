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

if [ "$EJ_CONTESTS" != "" ]
then
	for dir in $EJ_CONTESTS
	do
		mkdir /home/judges/$dir
		sshfs ${EJ_MOUNT_HOST}:/home/judges/$dir /home/judges/$dir -o ServerAliveInterval=30,reconnect,ro,allow_other
	done
fi

sshfs ${EJ_MOUNT_HOST}:/home/ej-run-spool /home/ej-run-spool -o ServerAliveInterval=30,reconnect,allow_other
sshfs ${EJ_MOUNT_HOST}:/home/ej-compile-spool /home/ej-compile-spool -o ServerAliveInterval=30,reconnect,allow_other

mkdir -p /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runmono /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runjava /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/rundotnet /var/lib/ejudge/scripts
cd /home/judges

if [ "${EJ_COMPILE}" = 1 ]
then
	export EJ_COMPILE_SERVER_ID="${EJ_QUEUE}"
	/opt/ejudge/libexec/ejudge/bin/ej-compile-control start
fi

if [ "${EJ_SUPER_RUN}" != "1" ]
then
	exit 0
fi


exec screen -d -m /home/ejudge/2start-super-run.sh
