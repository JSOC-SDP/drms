#!/bin/bash

# The configuration file is the instantiation of repserver.template.cfg

error=""
specific="no"

if [ $# -eq 1 ]
then
    # Must always be a config file
    conf="$1"
elif [ $# -eq 2 ]
then
    conf="$1"
    # User can also specify either the master or the slave to start up
    specific="$2"
else
    error="ERROR: Usage: $0 <server configuration file> [ master | slave ]"
fi

if [ ! $error == "" ]
then
    echo $error
    exit
fi

. "$conf"

echo "Starting the slon daemons"

if [ $specific == "master" -o $specific == "no" ]
then
slon -p $kMSMasterPIDFile -s 120000 -t 300000 $CLUSTERNAME "dbname=$MASTERDBNAME port=$MASTERPORT host=$MASTERHOST user=$REPUSER"  > $kMSLogDir/slon.node1.log 2>&1 &
fi

if [ $specific == "slave" -o $specific == "no" ]
then
slon -p $kMSSlavePIDFile -s 120000 -a /usr/local/pgsql/slon_logs -t 300000 $CLUSTERNAME "dbname=$SLAVEDBNAME port=$SLAVEPORT host=$SLAVEHOST user=$REPUSER"  > $kMSLogDir/slon.node2.log 2>&1 &
fi
