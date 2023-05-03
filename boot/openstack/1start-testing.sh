#! /bin/bash

. ~/user-data-fixed.sh
if head -1 ~/user-data.sh 2>/dev/null | grep "/bin/bash"
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

mkdir -p /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runmono /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/runjava /var/lib/ejudge/scripts
cp -p /home/judges/compile/scripts/rundotnet /var/lib/ejudge/scripts
cd /home/judges

OPT_NO=""
OPT_NR=""
[ "${EJ_COMPILE}" != 1 ] && OPT_NO=-no
[ "${EJ_SUPER_RUN}" != 1 ] && OPT_NR=-nr

AWS_HOST="http://169.254.169.254/latest/"
AWS_URL="${AWS_HOST}meta-data/"
AWS_INSTANCE_ID=`curl ${AWS_URL}instance-id 2>/dev/null`
AWS_LOCAL_HOSTNAME=`curl ${AWS_URL}local-hostname 2>/dev/null`
AWS_LOCAL_IP=`curl ${AWS_URL}local-ipv4 2>/dev/null`
AWS_PUBLIC_HOSTNAME=`curl ${AWS_URL}public-hostname 2>/dev/null`
AWS_PUBLIC_IP=`curl ${AWS_URL}public-ipv4 2>/dev/null`

[ "${AWS_PUBLIC_IP}" != "" ] || AWS_PUBLIC_IP="${AWS_LOCAL_IP}"
[ "${AWS_PUBLIC_HOSTNAME}" != "" ] || AWS_PUBLIC_HOSTNAME="${AWS_LOCAL_HOSTNAME}"

export AWS_INSTANCE_ID AWS_LOCAL_HOSTNAME AWS_LOCAL_IP AWS_PUBLIC_HOSTNAME AWS_PUBLIC_IP
export EJ_SUPER_RUN_ID

[ "${EJ_QUEUE}" = "" ] && EJ_QUEUE=super-run-z
[ "${EJ_TIMEOUT}" = "" ] && EJ_TIMEOUT=15
if [ "${EJ_TIMEOUT}" = "off" ]
then
    EJ_FULL_TIMEOUT=""
else
    EJ_FULL_TIMEOUT=" -ht ${EJ_TIMEOUT}"
fi

CACHE_DIR=/var/cache/ejudge
SUPER_RUN_CACHE="${CACHE_DIR}/super-run"

mkdir -p "${CACHE_DIR}"
rm -rf "${SUPER_RUN_CACHE}"
mkdir -p "${SUPER_RUN_CACHE}"

if [ "${EJ_SUPER_RUN_ID}" != "" ]
then
    exec /opt/ejudge/bin/ejudge-control ${OPT_NO} ${OPT_NR} --mirror ${SUPER_RUN_CACHE} --queue ${EJ_QUEUE} ${EJ_FULL_TIMEOUT} -hb --instance-id ${EJ_SUPER_RUN_ID} --agent ssh:${EJ_MOUNT_HOST} -hc /home/ejudge/3shutdown.sh -rc /home/ejudge/4reboot.sh --ip "${AWS_PUBLIC_IP}" -s start
fi
