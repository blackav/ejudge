#! /bin/bash

AWS_HOST="http://169.254.169.254/latest/"

curl "${AWS_HOST}user-data" > ~/user-data.sh 2>/dev/null
echo >> ~/user-data.sh
chmod +x ~/user-data.sh

if head -1 ~/user-data.sh | grep "/bin/bash"
then
    . ~/user-data.sh
    if [ "${EJ_SUPER_RUN}" = "1" -o "${EJ_COMPILE}" = "1" ]
    then
       ./1start-testing.sh 
    fi
else
    rm -f ~/user-data.sh
fi
