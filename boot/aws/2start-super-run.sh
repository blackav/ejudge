#! /bin/bash

AWS_HOST="http://169.254.169.254/latest/"
AWS_URL="${AWS_HOST}meta-data/"
AWS_INSTANCE_ID=`curl ${AWS_URL}instance-id 2>/dev/null`
AWS_LOCAL_HOSTNAME=`curl ${AWS_URL}local-hostname 2>/dev/null`
AWS_LOCAL_IP=`curl ${AWS_URL}local-ipv4 2>/dev/null`
AWS_PUBLIC_HOSTNAME=`curl ${AWS_URL}public-hostname 2>/dev/null`
AWS_PUBLIC_IP=`curl ${AWS_URL}public-ipv4 2>/dev/null`

curl "${AWS_HOST}user-data" > ~/user-data.sh 2>/dev/null
echo >> ~/user-data.sh
chmod +x ~/user-data.sh

if head -1 ~/user-data.sh | grep "/bin/bash"
then
    . ~/user-data.sh
else
    rm -f ~/user-data.sh
fi

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

mkdir /tmp/ejudge
exec /opt/ejudge/libexec/ejudge/bin/ej-super-run -m /tmp/ejudge/super-run -p ${EJ_QUEUE} ${EJ_FULL_TIMEOUT} -hc /home/ejudge/3shutdown.sh -hb -e /home/judges/compile/scripts/=/var/lib/ejudge/scripts/ --instance-id ${EJ_SUPER_RUN_ID}-run --agent ssh:${EJ_MOUNT_HOST}
