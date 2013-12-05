#!/bin/bash
set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 <user_name> <host> <ssh_key_file_pub> <password>"
    exit 1
fi

USERNAME=$1
HOST=$2
SSH_KEY_FILE_PUB=$3
PASSWORD=$4

MAX_WAIT_SECONDS=300

BASEDIR=$(dirname $0)

. $BASEDIR/utils.sh

ssh-keygen -R $HOST

PUBKEYFILE=`mktemp -u /tmp/ssh_key_pub.XXXXXX`

wait_for_listening_port $HOST 22 $MAX_WAIT_SECONDS
$BASEDIR/scppass.sh $SSH_KEY_FILE_PUB $USERNAME@$HOST:$PUBKEYFILE "$PASSWORD"
$BASEDIR/sshpass.sh $USERNAME@$HOST "$PASSWORD" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat $PUBKEYFILE >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (\[ ! -x /sbin/restorecon \] || restorecon -R -v ~/.ssh)"


