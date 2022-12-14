#!/bin/bash

# Environment variables are in the repserver.cfg file.

# When we run publish_series.sh, we create a second replication
# set that contains just the table that we want to add to the 
# original replication set. Then we merge the second replication
# set into the original one. The process results in the 
# dropping of the second (temporary) replication set.
#
# If for some reason something fails, we might end up with the second
# replication set not getting dropped. This script will
# drop that second replication set
#
# IMPORTANT!!! Do not drop or alter any table part of the second
# replication set before running this script. Otherwise, you'll
# delete something that slony expects to be there. 

# In the drop set command, the "id" refers to the ID of the replication set.
# id 2 is the temporary one and it is the one we want to drop.  
# The "origin" refers to which node is the master. Since we have no plans on changing 
# master to hmidb2 ever, this should always be 1

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

cluster name = $CLUSTERNAME;

node 1 admin conninfo = 'dbname=$MASTERDBNAME host=$MASTERHOST port=$MASTERPORT user=$REPUSER';
node 2 admin conninfo = 'dbname=$SLAVEDBNAME host=$SLAVEHOST port=$SLAVEPORT user=$REPUSER';

drop set ( id = 2, origin = 1);

_EOF_