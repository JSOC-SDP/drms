#!/bin/bash

if [ $# -eq 1 ]
then
    # Must always be a config file
    conf="$1"
else
    echo "ERROR: Usage: $0 <server configuration file>"
    exit 1
fi

. "$conf"

slonik <<_EOF_
# ----
cluster name = $CLUSTERNAME ;

# Admin conninfo's are used by the slonik program to connect
# to the node databases.  So these are the PQconnectdb arguments
# that connect from the administrators workstation (where
# slonik is executed).
# ----
node 1 admin conninfo = 'dbname=$MASTERDBNAME host=$MASTERHOST port=$MASTERPORT user=$REPUSER';
node 2 admin conninfo = 'dbname=$SLAVEDBNAME host=$SLAVEHOST port=$SLAVEPORT user=$REPUSER';

# ----
# Node 2 subscribes set 1
# ----
EXECUTE SCRIPT ( SET ID = 1, FILENAME = '/usr/local/pgsql/slony_init/test.sql', EVENT NODE = 1);

_EOF_
