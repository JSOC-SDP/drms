#!/bin/sh
# ----------
# slony1_dump.sh
#
# $Id: sdo_slony1_dump.sh,v 1.16 2016/04/22 06:24:18 arta Exp $
#
#	This script creates a special data only dump from a subscriber
#	node. The stdout of this script, fed into psql for a database that
#	has the user schema of the replicated database installed, will
#	prepare that database for log archive application.
# ----------

# ----
# Check for correct usage
# ----
if test $# -lt 6 ; then
	echo "usage: $0 <subscriber-dbname> <clustername> <port> <new_subscriber> <output counter filename> <tablist>" >&2
	echo "         new_subscriber = 1 for yes/true and 0 for no/false" >&2
	echo "         tablist =  a list of tables separated by white space" >&2
	exit 1
fi

# ----
# Remember call arguments and get the nodeId of the DB specified
# ----
dbname=$1
shift
cluster=$1
shift
port="$1"
shift
new_subscriber="$1"
shift
output_filecounter="$1";
shift;

clname="\"_$cluster\""
pgc="\"pg_catalog\""
nodeid=`psql -p $port -q -At -c "select \"_$cluster\".getLocalNodeId('_$cluster')" $dbname`

oldIFS="$IFS"
IFS="${IFS},"

tabs="$1"
shift
while [ $# -gt 0 ] ; do
	tabs="${tabs} $1"
	shift
done
IFS="$oldIFS"


# ----
# Construct a list of all replicated-table IDs that the subscribing node would like to subscribe to.
# This list of IDs will be saved in $tables.
# ----

# $tabs is an array of table names being subscribed to (like [hmi.v_45s hmi.m_720s]) by the subscribing node.
tabSQL1="select tab_id from $clname.sl_table, $clname.sl_set "
tabSQL1="${tabSQL1} where tab_set = set_id "
tabSQL3="and exists (select 1 from $clname.sl_subscribe "
tabSQL3="${tabSQL3} where sub_set = set_id and sub_receiver = $nodeid) "

# Split the table names into namespaces and relation names.
for I in `echo ${tabs}`; do
	#echo "[$I]"
	IFS="${IFS}."
	set - $I
	IFS="$oldIFS"

	#echo "[$1] [$2]"
	tabSQL2="and  tab_nspname = '$1' and tab_relname = '$2' "
	ret=`echo "${tabSQL1} ${tabSQL2} ${tabSQL3} " | psql -p $port -q -At -d $dbname `
	set - $ret
	tables="$tables $ret"
done

#for tab in $tables; do
	#echo "tab= [$tab]"
#done


#exit
#tables=`psql -p $port -q -At -d $dbname -c \
		#"select tab_id from $clname.sl_table, $clname.sl_set
				#where tab_set = set_id
					#and tab_relname in ($tabs)
					#and exists (select 1 from $clname.sl_subscribe
							#where sub_set = set_id
								#and sub_receiver = $nodeid)"`


# Create a set of variables named tabname_XX, where XX is the replicated-table ID of a table being subscribed to. For example,
# tabname_3 is a variable holding the string "hmi.m_45s".
for tab in $tables ; do
	eval tabname_$tab=`psql -p $port -q -At -d $dbname -c \
			"select $pgc.quote_ident(tab_nspname) || '.' || 
					$pgc.quote_ident(tab_relname) from 
					$clname.sl_table where tab_id = $tab"`
done

# ----
# Get a list of all replicated sequence ID's this subscriber receives,
# and remember the sequence names.
# ----
#-- sequences=`psql -p $port -q -At -d $dbname -c \
#-- 		"select seq_id from $clname.sl_sequence, $clname.sl_set
#-- 				where seq_set = set_id
#-- 					and exists (select 1 from $clname.sl_subscribe
#-- 							where sub_set = set_id
#-- 								and sub_receiver = $nodeid)"`
#-- for seq in $sequences ; do
#-- 	eval seqname_$seq=`psql -p $port -q -At -d $dbname -c \
#-- 			"select $pgc.quote_ident(seq_nspname) || '.' || 
#-- 					$pgc.quote_ident(seq_relname) from 
#-- 					$clname.sl_sequence where seq_id = $seq"`
#-- done


# ----
# Emit SQL code to create the slony specific object required
# in the remote database.
# ----
if [ $new_subscriber -eq 1 ] ; then
cat <<_EOF_

-- ----------------------------------------------------------------------
-- SCHEMA $clname
-- ----------------------------------------------------------------------
CREATE SCHEMA $clname;

-- ----------------------------------------------------------------------
-- TABLE sl_sequence_offline
-- ----------------------------------------------------------------------
CREATE TABLE $clname.sl_sequence_offline (
	seq_id				int4,
	seq_relname			name NOT NULL,
	seq_nspname			name NOT NULL,

	CONSTRAINT "sl_sequence-pkey"
		PRIMARY KEY (seq_id)
);


-- ----------------------------------------------------------------------
-- TABLE sl_archive_tracking
-- ----------------------------------------------------------------------
CREATE TABLE $clname.sl_archive_tracking (
	at_counter			bigint,
	at_created			timestamp,
	at_applied			timestamp
);

-- -----------------------------------------------------------------------------
-- FUNCTION sequenceSetValue_offline (seq_id, last_value)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION $clname.sequencesetvalue_offline(int4, int8) RETURNS int4
AS '
declare
	p_seq_id			alias for \$1;
	p_last_value		alias for \$2;
	v_fqname			text;
begin
	-- ----
	-- Get the sequences fully qualified name
	-- ----
	select "pg_catalog".quote_ident(seq_nspname) || ''.'' ||
			"pg_catalog".quote_ident(seq_relname) into v_fqname
		from $clname.sl_sequence_offline
		where seq_id = p_seq_id;
	if not found then
		raise exception ''Slony-I: sequence % not found'', p_seq_id;
	end if;

	-- ----
	-- Update it to the new value
	-- ----
	execute ''select setval('''''' || v_fqname ||
			'''''', '''''' || p_last_value || '''''')'';
	return p_seq_id;
end;
' language plpgsql;
-- ---------------------------------------------------------------------------------------
-- FUNCTION finishTableAfterCopy(table_id)
-- ---------------------------------------------------------------------------------------
-- This can just be a simple stub function; it does not need to do anything...
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION $clname.finishTableAfterCopy(int4) RETURNS int4 AS
  'select 1'
language sql;

-- ---------------------------------------------------------------------------------------
-- FUNCTION archiveTracking_offline (new_counter, created_timestamp)
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION $clname.archivetracking_offline(int8, timestamp) RETURNS int8
AS '
declare
	p_new_seq	alias for \$1;
	p_created	alias for \$2;
	v_exp_seq	int8;
	v_old_seq	int8;
begin
	select at_counter into v_old_seq from $clname.sl_archive_tracking;
	if not found then
		raise exception ''Slony-I: current archive tracking status not found'';
	end if;

	v_exp_seq := p_new_seq - 1;
	if v_old_seq <> v_exp_seq then
		raise exception ''Slony-I: node is on archive counter %, this archive log expects %'', 
			v_old_seq, v_exp_seq;
	end if;
	raise notice ''Slony-I: Process archive with counter % created %'', p_new_seq, p_created;

	update $clname.sl_archive_tracking
		set at_counter = p_new_seq,
			at_created = p_created,
			at_applied = CURRENT_TIMESTAMP;
	return p_new_seq;
end;
' language plpgsql;

_EOF_
fi


# ----
# The remainder of this script is written in a way that
# all output is generated by psql inside of one serializable
# transaction, so that we get a consistent snapshot of the
# replica.
# ----

# We need to run the log parser and edit the slony_parser.txt
# file at times relative to the database activity. For example, we must first
# lock the series tables before running the log parser and doing the dump. 
# And we must edit slony_parser.txt after the
# log-parser has run, but before the series tables are unlocked (which happens after the enclosing
# transaction terminates). Shell has no way of interspersing db commands with non-db commands - you
# can't keep a transaction to the db open and then alternate between db commands and non-db commands.
# Shell cannot keep a transaction open and issue a mix of db and non-db commands. Instead, call a Perl Script.

for tab in $tables ; do
    eval tabname=\$tabname_$tab # $tabname now has a name of a table being subscribed to (like "hmi.m_45s").
    if [ -z "$sublist" ] 
    then
        sublist="$tabname"
        echo "adding $tabname to sublist" > $kSMlogDir/slony1_dump.$node.log
    else
        sublist="$sublist,$tabname"
        echo "adding $tabname to sublist" >> $kSMlogDir/slony1_dump.$node.log
    fi

    if [ -z "$idlist" ]
    then
        idlist="$tab"
        echo "adding $tab to sublist" >> $kSMlogDir/slony1_dump.$node.log
    else
        idlist="$idlist,$tab"
        echo "adding $tab to sublist" >> $kSMlogDir/slony1_dump.$node.log
    fi
done

# The stdout of from this call will contain SQL that runs on the client end. It dumps the series tables. $config_file is defined in subscription_update
# (old school system) or in manage-subs.py.
cmd="$kJSOCRoot/base/drms/replication/subscribe_manage/dumpreptables.pl config=$config_file client=$node sublist=$sublist idlist=$idlist newcl=$new_subscriber filectr=$output_filecounter 2>>$kSMlogDir/slony1_dump.$node.log"
echo "Executing $cmd" >&2
$cmd

if [ $? -ne 0 ]
then
    echo "Failure running dumpreptables.pl." >&2
    exit 1
else
    echo "Success running dumpreptables.pl." >&2
fi

# ----
# Emit the commit for the dump to stdout.
# ----
#echo "commit;"
echo "-- dump complete"
