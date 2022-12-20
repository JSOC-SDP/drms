-- creates all DRMS database types and functions:
--   drms_series() returns a table of all <namespace>.drms_series values
--   drms_keyword() returns a table of all <namespace>.drms_keyword values
--   drms_segment() returns a table of all <namespace>.drms_segment values
--   drms_link() returns a table of all <namespace>.drms_link values
--   drms_session() returns a table of all <namespace>.drms_session values
--   drms_replicated() returns a table of Slony-replicated series
--   drms_linkedkeyword() returns a table of parent series/keyword and child series/keyword
--   drms_followkeywordlink() returns a table of child keyword information
--   drms_linkedsegment() returns a table of parent series/segment and child series/segment
--   drms_followsegmentlink() returns a table of child segment information
--   image_exists() returns 't' if the provided quality keyword value indicates the existence of a segment file
--   updateshadow() - a trigger function that updates a series' table shadow table when a rows is inserted into the series

-- DRMS Keyword data type and function to display keyword information for all namespaces
DROP TYPE IF EXISTS drmskw CASCADE;

CREATE TYPE drmskw AS (
    seriesname  text,
    keywordname text,
    linkname    text,
    targetkeyw  text,
    type        text,
    defaultval  text,
    format      text,
    unit        text,
    islink      int8,
    isconstant  int8,
    persegment  int8,
    description text );

CREATE OR REPLACE FUNCTION drms_keyword() RETURNS SETOF drmskw AS $$
DECLARE
  ns  RECORD;
  rec drmskw%ROWTYPE;
  next_row REFCURSOR;
BEGIN
  FOR ns IN SELECT name || '.drms_keyword' as tn FROM admin.ns order by name LOOP
     OPEN next_row FOR EXECUTE 'SELECT * FROM ' || ns.tn;
     LOOP
       FETCH next_row INTO rec;
       IF NOT FOUND THEN
          EXIT;
       END IF;
       RETURN NEXT rec;
     END LOOP;
     CLOSE next_row;
  END LOOP;
  RETURN;
END;
$$
LANGUAGE plpgsql;

-- DRMS Series data type and function to display series information for all namespaces
DROP TYPE IF EXISTS drmsseries CASCADE;

CREATE TYPE drmsseries AS (
    seriesname  text,
    author      text,
    owner       text,
    unitsize    int8,
    archive     int8,
    retention   int8,
    tapegroup   int8,
    primary_idx text,
    created     text,
    description text,
    dbidx       text,
    version     text );

CREATE OR REPLACE FUNCTION drms_series() RETURNS SETOF drmsseries AS $$
DECLARE
  ns  RECORD;
  rec drmsseries%ROWTYPE;
  next_row REFCURSOR;
BEGIN
  FOR ns IN SELECT name || '.drms_series' as tn FROM admin.ns order by name LOOP
     OPEN next_row FOR EXECUTE 'SELECT * FROM ' || ns.tn;
     LOOP
       FETCH next_row INTO rec;
       IF NOT FOUND THEN
          EXIT;
       END IF;
       RETURN NEXT rec;
     END LOOP;
     CLOSE next_row;
  END LOOP;
  RETURN;
END;
$$
LANGUAGE plpgsql;


-- DRMS Segment data type and function to display segment information for all namespaces
DROP TYPE IF EXISTS drmssg CASCADE;

CREATE TYPE drmssg AS (
    seriesname  text,
    segmentname text,
    segnum      int8,
    scope       text,
    type        text,
    naxis       int8,
    axis        text,
    unit        text,
    protocol    text,
    description text,
    islink      int8,
    linkname    text,
    targetseg   text,
    cseg_recnum int8 );

CREATE OR REPLACE FUNCTION drms_segment() RETURNS SETOF drmssg AS $$
DECLARE
  ns  RECORD;
  rec drmssg%ROWTYPE;
  next_row REFCURSOR;
BEGIN
  FOR ns IN SELECT name || '.drms_segment' as tn FROM admin.ns order by name LOOP
     OPEN next_row FOR EXECUTE 'SELECT * FROM ' || ns.tn;
     LOOP
       FETCH next_row INTO rec;
       IF NOT FOUND THEN
          EXIT;
       END IF;
       RETURN NEXT rec;
     END LOOP;
     CLOSE next_row;
  END LOOP;
  RETURN;
END;
$$
LANGUAGE plpgsql;

-- DRMS Session data type and function to display session information for all namespaces
DROP TYPE IF EXISTS drmssession CASCADE;

CREATE TYPE drmssession AS (
     sessionid           bigint,
     hostname            text,
     port                int8,
     pid                 int8,
     sunum               bigint,
     sudir               text,
     username            text,
     starttime           text,
     lastcontact         text,
     endtime             text,
     clients             int8,
     status              text,
     sums_thread_status  text,
     jsoc_version        text );

CREATE OR REPLACE FUNCTION drms_session() RETURNS SETOF drmssession AS $$
DECLARE
  ns  RECORD;
  rec drmssession%ROWTYPE;
  next_row REFCURSOR;
BEGIN
  FOR ns IN SELECT name as tn FROM admin.ns order by name LOOP
     OPEN next_row FOR EXECUTE 'SELECT * FROM ' || ns.tn || '.drms_session';
     LOOP
       FETCH next_row INTO rec;
       rec.username := rec.username || '(' || ns.tn || ')';
       IF NOT FOUND THEN
          EXIT;
       END IF;
       RETURN NEXT rec;
     END LOOP;
     CLOSE next_row;
  END LOOP;
  RETURN;
END;
$$
LANGUAGE plpgsql;

-- function to return table of Slony-replicated database tables
DROP TYPE IF EXISTS rep_item CASCADE;

CREATE TYPE rep_item AS (
    tab_id      int8,
    tab_relname varchar(255),
    tab_nspname varchar(255),
    tab_set     int8,
    tab_idxname varchar(255),
    tab_comment text );

CREATE OR REPLACE function drms_replicated() RETURNS SETOF rep_item AS $$
	DECLARE
	     tn RECORD;
	     rec rep_item%ROWTYPE;
             clustercursor REFCURSOR;
	     tabcursor REFCURSOR;
	     query_obj TEXT;
	     q_string TEXT := 'SELECT schemaname from pg_tables where tablename like $qtag$sl_table%$qtag$';
--Get Slony schemanames --
  BEGIN
	-- Create a cursor of cluster names --
     FOR tn IN SELECT schemaname as sn from pg_tables where tablename like 'sl_table' ORDER BY schemaname LOOP
        OPEN clustercursor for EXECUTE 'SELECT tab_id, tab_relname, tab_nspname, tab_set, tab_idxname, tab_comment FROM ' || tn.sn || '.sl_table' ;
	LOOP
	    FETCH clustercursor INTO rec;
	    IF NOT FOUND THEN
	          EXIT;
            END IF;
            RETURN NEXT rec;
        END LOOP;
        CLOSE clustercursor;
     END LOOP;
     RETURN;
END;
$$
LANGUAGE 'plpgsql';

-- function to return the linked ( series, keyword ) for the given ( series, keyword ), if such a link exists
DROP TYPE IF EXISTS serieskey CASCADE;
CREATE TYPE serieskey AS
(
    series varchar(64),
    keyword varchar(32),
    linkedseries varchar(64),
    linkedkeyword varchar(32)
);

-- ( `dataseries`, `datakeyword` ) - the DRMS keyword for which a linked keyword will be returned
-- output - ( <original DRMS keyword DRMS series>, <original DRMS keyword>, <linked DRMS keyword DRMS series>, <linked DRMS keyword> ); if no such link exists then ( <original DRMS keyword DRMS series>, <original DRMS keyword>, NULL, NULL ) is returned
CREATE OR REPLACE FUNCTION drms_linkedkeyword(dataseries varchar, datakeyword varchar) RETURNS SETOF serieskey AS $$
DECLARE
    parsed varchar[2];
    namespace varchar;
    relation varchar;
BEGIN
    SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
    namespace := parsed[1];
    relation := parsed[2];

    IF datakeyword IS NULL OR datakeyword = '' THEN
        RETURN QUERY EXECUTE 'SELECT K.seriesname::VARCHAR AS series, K.keywordname::VARCHAR as keyword, L.target_seriesname::VARCHAR AS linkedseries, K.targetkeyw::VARCHAR AS linkedkeyword FROM ' || quote_ident(namespace) || '.drms_keyword AS K LEFT OUTER JOIN ' || quote_ident(namespace) || '.drms_link AS L ON lower(K.linkname) = lower(L.linkname) AND lower(K.seriesname) = lower(L.seriesname) WHERE lower(K.seriesname) = $1' USING lower(dataseries);
    ELSE
        RETURN QUERY EXECUTE 'SELECT K.seriesname::VARCHAR AS series, K.keywordname::VARCHAR as keyword, L.target_seriesname::VARCHAR AS linkedseries, K.targetkeyw::VARCHAR AS linkedkeyword FROM ' || quote_ident(namespace) || '.drms_keyword AS K LEFT OUTER JOIN ' || quote_ident(namespace) || '.drms_link AS L ON lower(K.linkname) = lower(L.linkname) AND lower(K.seriesname) = lower(L.seriesname) WHERE lower(K.seriesname) = $1 AND lower(K.keywordname) = $2' USING lower(dataseries), lower(datakeyword);
    END IF;
END;
$$
LANGUAGE plpgsql;

-- function to return the keyword information of the given ( series, keyword ); if the given ( series, keyword ) is linked to a linked ( series, keyword ), then information from the linked keyword will be returned, otherwise all information is derived from the given ( series, keyword )
DROP TYPE IF EXISTS keyinfo CASCADE;
CREATE TYPE keyinfo AS
(
    series varchar(64),
    keyword varchar(32),
    datatype varchar(16),
    keyworddefault text,
    format varchar(32),
    unit varchar(32),
    isconstant boolean,
    flags integer,
    description text
);

CREATE OR REPLACE FUNCTION drms_followkeywordlink(dataseries varchar, datakeyword varchar) RETURNS SETOF keyinfo AS $$
DECLARE
    parsed varchar[2];
    namespace varchar;
    relation varchar;
    origkeyword varchar;
    linkedseries varchar;
    linkedkeyword varchar;
    linkmaprecord RECORD;
    origflags integer;
BEGIN
    -- origkeyword is needed in the case that the caller provides NULL for datakeyword (requesting information about all keyword in a series)
    FOR linkmaprecord IN SELECT K.keyword, K.linkedseries, K.linkedkeyword FROM drms_linkedkeyword(dataseries, datakeyword) AS K LOOP
        origkeyword := linkmaprecord.keyword;
        linkedseries := linkmaprecord.linkedseries;
        linkedkeyword := linkmaprecord.linkedkeyword;

        SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
        namespace := parsed[1];
        relation := parsed[2];

        LOOP
            IF linkedseries IS NULL THEN
                -- not a linked series
                -- return original series and keyword name so the caller can locate the information by input values easily
                RETURN QUERY EXECUTE 'SELECT seriesname::varchar AS series, keywordname::varchar AS keyword, type::varchar AS datatype, defaultval::text AS keyworddefault, format::varchar AS format, unit::varchar AS unit, (isconstant=1)::boolean AS isconstant, persegment::integer AS flags, description::text as description FROM ' || quote_ident(namespace) || '.drms_keyword WHERE lower(seriesname) = $1 AND lower(keywordname) = $2' USING lower(dataseries), lower(origkeyword);
                EXIT;
            ELSE
                -- linked series
                -- must return original implicit (bit 1), internal-prime (bit 2), and external-prime (bit 3) flags values, but linked per-segment (bit 0) value (select `flags` from the linked series and extract the bit 0 value, then poke that value into the original series' `flags` value)
                -- also, must return original rank (top 16 bits)
                EXECUTE 'SELECT persegment FROM ' || namespace || '.drms_keyword WHERE lower(seriesname) = lower(' || quote_literal(dataseries) || ') AND lower(keywordname) = lower(' || quote_literal(origkeyword) || ')' INTO origflags;
                RETURN QUERY EXECUTE 'SELECT ' || quote_literal(dataseries) || '::varchar AS series, ' || quote_literal(origkeyword) || '::varchar AS keyword, datatype, keyworddefault, format, unit, isconstant, ((' || quote_literal(origflags) || '::integer::bit(32) & X''FFFFFFFE'') | (flags::bit(32) & X''00000001''))::integer AS flags, description FROM drms_followkeywordlink(' || quote_literal(linkedseries) || ',' || quote_literal(linkedkeyword) || ')';
                EXIT;
            END IF;
        END LOOP;
    END LOOP;
END;
$$
LANGUAGE plpgsql;

-- ugh, new version of drms_followkeywordlink2; we need to know the value of the isconstant column, not whether or not it equals zero; the wsgi app uses this version of drms_followkeywordlink() in get_series_info.py
DROP TYPE IF EXISTS keyinfo2 CASCADE;
CREATE TYPE keyinfo2 AS
(
    series varchar(64),
    keyword varchar(32),
    link varchar(32),
    link_type varchar(16),
    datatype varchar(16),
    keyworddefault text,
    format varchar(32),
    unit varchar(32),
    scope_type integer,
    flags integer,
    description text
);

CREATE OR REPLACE FUNCTION drms_followkeywordlink2(dataseries varchar, datakeyword varchar) RETURNS SETOF keyinfo2 AS $$
DECLARE
    parsed varchar[2];
    namespace varchar;
    relation varchar;
    origkeyword varchar;
    linkedseries varchar;
    linkedkeyword varchar;
    linkmaprecord RECORD;
    parent_key_values RECORD;
    link_type varchar;
BEGIN
    -- origkeyword is needed in the case that the caller provides NULL for datakeyword (requesting information about all keyword in a series)
    FOR linkmaprecord IN SELECT K.keyword, K.linkedseries, K.linkedkeyword FROM drms_linkedkeyword(dataseries, datakeyword) AS K LOOP
        origkeyword := linkmaprecord.keyword;
        linkedseries := linkmaprecord.linkedseries;
        linkedkeyword := linkmaprecord.linkedkeyword;

        SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
        namespace := parsed[1];
        relation := parsed[2];

        LOOP
            IF linkedseries IS NULL THEN
                -- not a linked series
                -- return original series and keyword name so the caller can locate the information by input values easily
                RETURN QUERY EXECUTE 'SELECT seriesname::varchar AS series, keywordname::varchar AS keyword, NULL::varchar AS link, NULL::varchar AS link_type, type::varchar AS datatype, defaultval::text AS keyworddefault, format::varchar AS format, unit::varchar AS unit, isconstant::integer AS scope_type, persegment::integer AS flags, description::text as description FROM ' || quote_ident(namespace) || '.drms_keyword WHERE lower(seriesname) = $1 AND lower(keywordname) = $2' USING lower(dataseries), lower(origkeyword);
                EXIT;
            ELSE
                -- linked series
                -- must return original implicit (bit 1), internal-prime (bit 2), and external-prime (bit 3) flags values, but linked per-segment (bit 0) value (select `flags` from the linked series and extract the bit 0 value, then poke that value into the original series' `flags` value)
                -- also, must return original rank (top 16 bits)
                EXECUTE 'SELECT linkname, persegment FROM ' || namespace || '.drms_keyword WHERE lower(seriesname) = lower(' || quote_literal(dataseries) || ') AND lower(keywordname) = lower(' || quote_literal(origkeyword) || ')' INTO parent_key_values;

                EXECUTE 'SELECT type FROM ' || namespace || '.drms_link WHERE lower(seriesname) = lower(' || quote_literal(dataseries) || ') AND lower(linkname) = lower(' || quote_literal(parent_key_values.linkname) || ')' INTO link_type;

                RETURN QUERY EXECUTE 'SELECT ' || quote_literal(dataseries) || '::varchar AS series, ' || quote_literal(origkeyword) || '::varchar AS keyword, ' || quote_literal(parent_key_values.linkname) || '::varchar AS link, ' || quote_literal(link_type) || '::varchar AS link_type, ' || 'datatype, keyworddefault, format, unit, scope_type, ((' || quote_literal(parent_key_values.persegment) || '::integer::bit(32) & X''FFFFFFFE'') | (flags::bit(32) & X''00000001''))::integer AS flags, description FROM drms_followkeywordlink2(' || quote_literal(linkedseries) || ',' || quote_literal(linkedkeyword) || ')';
                EXIT;
            END IF;
        END LOOP;
    END LOOP;
END;
$$
LANGUAGE plpgsql;

DROP TYPE IF EXISTS seriesseg CASCADE;
CREATE TYPE seriesseg AS
(
    series varchar(64),
    segment varchar(32),
    linkedseries varchar(64),
    linkedsegment varchar(32)
);

CREATE OR REPLACE FUNCTION drms_linkedsegment(dataseries varchar, datasegment varchar) RETURNS SETOF seriesseg AS $$
DECLARE
    parsed varchar[2];
    namespace varchar;
    relation varchar;
BEGIN
    SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
    namespace := parsed[1];
    relation := parsed[2];

    IF datasegment IS NULL OR datasegment = '' THEN
        RETURN QUERY EXECUTE 'SELECT S.seriesname::VARCHAR AS series, S.segmentname::VARCHAR as segment, L.target_seriesname::VARCHAR AS linkedseries, S.targetseg::VARCHAR AS linkedsegment FROM ' || quote_ident(namespace) || '.drms_segment AS S LEFT OUTER JOIN ' || quote_ident(namespace) || '.drms_link AS L ON lower(S.linkname) = lower(L.linkname) AND lower(S.seriesname) = lower(L.seriesname) WHERE lower(S.seriesname) = $1' USING lower(dataseries);
    ELSE
        RETURN QUERY EXECUTE 'SELECT S.seriesname::VARCHAR AS series, S.segmentname::VARCHAR as segment, L.target_seriesname::VARCHAR AS linkedseries, S.targetseg::VARCHAR AS linkedsegment FROM ' || quote_ident(namespace) || '.drms_segment AS S LEFT OUTER JOIN ' || quote_ident(namespace) || '.drms_link AS L ON lower(S.linkname) = lower(L.linkname) AND lower(S.seriesname) = lower(L.seriesname) WHERE lower(S.seriesname) = $1 AND lower(S.segmentname) = $2' USING lower(dataseries), lower(datasegment);
    END IF;
END;
$$
LANGUAGE plpgsql;

-- function to return the segment information of the given ( series, segment ); if the given ( series, segment ) is linked to a linked ( series, segment ), then information from the linked segment will be returned, otherwise all information is derived from the given ( series, segment )
DROP TYPE IF EXISTS seginfo CASCADE;
CREATE TYPE seginfo AS
(
    series varchar(64),
    segment varchar(32),
    datatype varchar(16),
    segnum smallint,
    scope varchar(16),
    numaxes integer,
    dimensions varchar(128),
    unit varchar(32),
    protocol varchar(32),
    description text
);

CREATE OR REPLACE FUNCTION drms_followsegmentlink(dataseries varchar, datasegment varchar) RETURNS SETOF seginfo AS $$
DECLARE
    parsed varchar[2];
    namespace varchar;
    relation varchar;
    origsegment varchar;
    linkedseries varchar;
    linkedsegment varchar;
    linkmaprecord RECORD;
    segnum smallint;
BEGIN
    -- origsegment is needed in the case that the caller provides NULL for datasegment (requesting information about all segments in a series)
    FOR linkmaprecord IN SELECT S.segment, S.linkedseries, S.linkedsegment FROM drms_linkedsegment(dataseries, datasegment) AS S LOOP
        origsegment := linkmaprecord.segment;
        linkedseries := linkmaprecord.linkedseries;
        linkedsegment := linkmaprecord.linkedsegment;

        SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
        namespace := parsed[1];
        relation := parsed[2];

        LOOP
            IF linkedseries IS NULL THEN
                -- not a linked series
                -- return original series and segment name so the caller can locate the information by input values easily
                RETURN QUERY EXECUTE 'SELECT seriesname::varchar AS series, segmentname::varchar AS segment, type::varchar AS datatype, segnum::smallint AS segnum, scope::varchar, naxis::integer AS numaxes, axis::varchar AS dimensions, unit::varchar, protocol::varchar, description FROM ' || quote_ident(namespace) || '.drms_segment WHERE lower(seriesname) = $1 AND lower(segmentname) = $2' USING lower(dataseries), lower(origsegment);
                EXIT;
            ELSE
                -- linked series
                -- must return original segment number here
                EXECUTE 'SELECT segnum::smallint FROM ' || namespace || '.drms_segment WHERE lower(seriesname) = lower(' || quote_literal(dataseries) || ') AND lower(segmentname) = lower(' || quote_literal(origsegment) || ')' INTO segnum;
                RETURN QUERY EXECUTE 'SELECT ' || quote_literal(dataseries) || '::varchar AS series, ' || quote_literal(origsegment) || '::varchar AS segment, datatype, ' || quote_literal(segnum) || '::smallint AS segnum, scope, numaxes, dimensions, unit, protocol, description FROM drms_followsegmentlink(' || quote_literal(linkedseries) || ',' || quote_literal(linkedsegment) || ')';
                EXIT;
            END IF;
        END LOOP;
    END LOOP;

END;
$$
LANGUAGE plpgsql;


-- function that returns 't' if the 32-bit pattern in `quality` indicates the existence of an image
CREATE OR REPLACE FUNCTION drms.image_exists(quality integer) RETURNS boolean AS
$$
DECLARE
  answer boolean;

BEGIN
  -- unless the top bit (bit 31) exists, an image is guaranteed to exist
  answer := (quality::bit(32) & X'80000000')::int = 0;
  RETURN answer;
END;
$$
LANGUAGE plpgsql;

-- This code block gets placed into an anonymous perl
-- subroutine, so we cannot declare global subroutines.
-- Instead, you have to create anonymous subroutines.
CREATE OR REPLACE FUNCTION public.updateshadow() RETURNS trigger AS $updateshadow$
    use strict;
    use warnings;
    use constant kShadowSuffix => '_shadow';

    my($fGetPkeys);
    my($fCheckKeyType);
    my($fShadowExists);
    my($fCleanKey);
    my($fIsGroupNew);
    my($fUpdateShadow);
    my($fInsertIntoShadow);
    my($fWasGroupDeleted);
    my($fDeleteFromShadow);

    # Anonymous-function definitions
    $fCheckKeyType = sub {
                            # If keyword has a data type of string, then append a '*'
                            # to the end of the keyword name. We need to mark
                            # such keywords because the SQL that queries keyword
                            # values needs to treat string keywords differently
                            # from other types of keywords. For string keywords
                            # their values must be enclosed in single quotes.
                            my($ns, $seriesname, $keyname, $statusR) = @_;
                            my($stmnt);
                            my($errmsg);
                            my($finalkeyname);
                            my($rv);

                            if ($$statusR)
                            {
                                return ();
                            }

                            $finalkeyname = lc(($keyname =~ /\s*(\S+)\s*/)[0]);

                            $stmnt = "SELECT type FROM $ns.drms_keyword WHERE lower(seriesname) = '$seriesname' AND lower(keywordname) = '$keyname'";

                            $rv = spi_exec_query($stmnt, 1);

                            if ($rv->{status} eq 'SPI_OK_SELECT' && $rv->{processed} == 1)
                            {
                                if ($rv->{rows}[0]->{type} eq "string")
                                {
                                    # lib DRMS maps the string stored in the type field to an enum by comparing,
                                    # without regard to case, the string value to the strings in drms_type_names
                                    # (using the function drms_str2type()). I just hard-coded the string "string"
                                    # here.
                                    $finalkeyname = "$finalkeyname\*"
                                }

                                $$statusR = 0;
                            }
                            else
                            {
                                $errmsg = "Bad db query: $stmnt.";
                                elog(WARNING, $errmsg);
                                $$statusR = 1;
                            }

                            return $finalkeyname;
                        };

    $fGetPkeys = sub {
                    my($ns, $tab, $statusR) = @_;
                    my(@pkeys);
                    my($sname);
                    my($stmnt);
                    my($pkeysstr);
                    my(@draft);
                    my($cleankey);
                    my($mangled);
                    my($errmsg);
                    my($rv);

                    $sname = lc("$ns\.$tab");
                    $stmnt = "SELECT primary_idx FROM $ns\.drms_series WHERE lower(seriesname) = '$sname'";

                    # seriesname is THE prime-key, so this query can return at most one row.
                    $rv = spi_exec_query($stmnt, 1);

                    if ($rv->{status} eq 'SPI_OK_SELECT')
                    {
                        $pkeysstr = $rv->{rows}[0]->{primary_idx};

                        # Parse out prime-key keyword names.
                        @draft = split(',', $pkeysstr);

                        foreach my $key (@draft)
                        {
                            $cleankey = lc(($key =~ /\s*(\S+)\s*/)[0]);
                            $mangled = &{$fCheckKeyType}($ns, $sname, $cleankey, $statusR);
                            push(@pkeys, $mangled);
                        }
                    }
                    else
                    {
                        $errmsg = "Bad db query: $stmnt.";
                        elog(WARNING, $errmsg);
                        $$statusR = 1;
                    }

                    return @pkeys;
                    };

    $fShadowExists = sub {
                        my($ns, $tab, $statusR) = @_;
                        my($nrows);
                        my($stmnt);
                        my($errmsg);
                        my($rv);

                        $nrows = 0;
                        $stmnt = "SELECT * FROM pg_tables WHERE schemaname ILIKE '$ns' AND tablename ILIKE '$tab'";
                        $rv = spi_exec_query($stmnt, 1);

                        if ($rv->{status} eq 'SPI_OK_SELECT')
                        {
                            $nrows = $rv->{processed};
                            $$statusR = 0;
                        }
                        else
                        {
                            $errmsg = "Bad db query: $stmnt";
                            elog(WARNING, $errmsg);
                            $$statusR = 1;
                        }

                        return ($nrows == 1);
                        };

    $fCleanKey = sub {
                        my($keyin) = @_;

                        return ($keyin =~ /([^\*]+)(\*)?$/)[0];
                    };

    $fIsGroupNew = sub {
                        # Because of the way that PG first inserts all records into the series
                        # table for a given statement, THEN it calls the trigger function
                        # once per record inserted, we cannot use information in the series table
                        # to distinguish between the inserted records. If the insert statement
                        # causes three records to be inserted into the series table, then
                        # the trigger function will be called three times, but during each
                        # invocation, the series table will have had the three records already
                        # inserted. So, between the three calls to the trigger function,
                        # nothing will change in the series table.
                        #
                        # To determine if a group is new, we have to determine what group
                        # (prime-key value) the inserted record will belong to, and then
                        # check the shadow table to see if that group exists. If not, then
                        # IsGroupNew() should return true. Otherwise, it should return false.


                        my($recno, $ns, $tab, $pkeynamesR, $primekeyvalsH, $statusR) = @_;
                        my($sname);
                        my($shadow);
                        my($stmnt);
                        my($ikey);
                        my($cleankey);
                        my($newGroup);
                        my($errmsg);
                        my($rv);

                        $newGroup = 0;

                        $sname = lc("$ns\.$tab");
                        $shadow = $sname . &kShadowSuffix;

                        $stmnt = "SELECT count(*) FROM $shadow WHERE ";
                        $ikey = 0;
                        foreach my $key (@{$pkeynamesR})
                        {
                            $cleankey = &{$fCleanKey}($key);

                            if ($ikey > 0)
                            {
                                $stmnt = "$stmnt AND ";
                            }

                            if ($key =~ /\*$/)
                            {
                                $stmnt = "${stmnt}$cleankey = \'" . $primekeyvalsH->{$cleankey} . "\'";
                            }
                            else
                            {
                                $stmnt = "${stmnt}$cleankey = " . $primekeyvalsH->{$cleankey};
                            }

                            $ikey++;
                        }

                        # Execute the query - we expect to get one row / one column, the count of the
                        # number of records in the shadow table whose prime-key value matches the prime-key
                        # value of the record just inserted into the series table. The answer is either
                        # 0 (which implies that we need to create a new group) or 1 (which implies
                        # that group already exists).

                        $rv = spi_exec_query($stmnt, 1);

                        if ($rv->{status} eq 'SPI_OK_SELECT' && $rv->{processed} == 1)
                        {
                            $newGroup = ($rv->{rows}[0]->{count} == 0);                        }
                        else
                        {
                            $errmsg = "Bad db query: $stmnt.";
                            elog(WARNING, $errmsg);
                            $$statusR = 1;
                        }

                        return $newGroup;
                    };

    $fUpdateShadow = sub {
                            my($ns, $tab, $pkeynamesR, $primekeyvalsH, $recno, $inserted, $statusR) = @_;
                            my($sname);
                            my($stmnt);
                            my($keylist);
                            my($cleankey);
                            my($maxrec);
                            my($shadow);
                            my($ikey);
                            my($errmsg);
                            my($rv);

                            # SELECT max(recnum) FROM <series> WHERE <pkey1> = <pkeyval1> AND <pkey2> = <pkeyval2> ...

                            $sname = lc("$ns\.$tab");
                            $shadow = $sname . &kShadowSuffix;

                            # Loop through prime-key keywords.
                            $ikey = 0;
                            $keylist = "";
                            foreach my $key (@{$pkeynamesR})
                            {
                                $cleankey = &{$fCleanKey}($key);

                                if ($ikey > 0)
                                {
                                    $keylist = "$keylist AND ";
                                }

                                if ($key =~ /\*$/)
                                {
                                    $keylist = "${keylist}$cleankey = \'" . $primekeyvalsH->{$cleankey} . "\'";
                                }
                                else
                                {
                                    $keylist = "${keylist}$cleankey = " . $primekeyvalsH->{$cleankey};
                                }

                                $ikey++;
                            }

                            $stmnt = "SELECT max(recnum) FROM $sname WHERE $keylist";

                            # Execute the query. There will only be one record.
                            $rv = spi_exec_query($stmnt, 1);

                            if ($rv->{status} eq 'SPI_OK_SELECT' && $rv->{processed} == 1)
                            {
                                $maxrec = $rv->{rows}[0]->{max};
                            }
                            else
                            {
                                $errmsg = "Bad update db statement: $stmnt";
                                elog(WARNING, $errmsg);
                                $$statusR = 1;
                            }

                            if (defined($maxrec))
                            {
                                if ($inserted)
                                {
                                    if ($maxrec == $recno)
                                    {
                                        # The record just inserted into series is the newest version. Update the
                                        # corresponding records shadow-table record, using the prime-key values to
                                        # locate the shadow-table record.
                                        #
                                        # UPDATE <shadow> SET recnum = <recnum>, nrecords = nrecords + 1 WHERE <pkey1>=<pkey1val> AND <pkey2>=<pkey2val> AND ...

                                        $stmnt = "UPDATE $shadow SET recnum = $recno, nrecords = nrecords + 1 WHERE $keylist";

                                        # Updating a single record.
                                        $rv = spi_exec_query($stmnt);

                                        if ($rv->{status} ne 'SPI_OK_UPDATE' || $rv->{processed} != 1)
                                        {
                                            $errmsg = "Bad update db statement: $stmnt";
                                            elog(WARNING, $errmsg);
                                            $$statusR = 1;
                                        }
                                    }
                                    elsif ($maxrec > $recno)
                                    {
                                        # The record just inserted into series is an obsolete version. This
                                        # cannot happen if the record was inserted via DRMS. But it could
                                        # happen if somebody inserts a record by some other means. If this happens
                                        # then increment the nrecords column.
                                        #
                                        # UPDATE <shadow> SET nrecords = nrecords + 1 WHERE <pkey1>=<pkey1val> AND <pkey2>=<pkey2val> AND ...

                                        $stmnt = "UPDATE $shadow SET nrecords = nrecords + 1 WHERE $keylist";

                                        # Updating a single record.
                                        $rv = spi_exec_query($stmnt);

                                        if ($rv->{status} ne 'SPI_OK_UPDATE' || $rv->{processed} != 1)
                                        {
                                            $errmsg = "Bad update db statement: $stmnt.";
                                            elog(WARNING, $errmsg);
                                            $$statusR = 1;
                                        }
                                    }
                                    else
                                    {
                                        $errmsg = "What happened to the record just inserted?";
                                        elog(WARNING, $errmsg);
                                        $$statusR = 1;
                                    }
                                }
                                else
                                {
                                    if ($maxrec > $recno)
                                    {
                                        # An obsolete version of the DRMS record was deleted. Update the nrecords column only.
                                        # UPDATE <shadow> SET nrecords = nrecords - 1 WHERE <pkey1>=<pkey1val> AND <pkey2>=<pkey2val> AND ...

                                        $stmnt = "UPDATE $shadow SET nrecords = nrecords - 1 WHERE $keylist";

                                        # Updating a single record.
                                        $rv = spi_exec_query($stmnt);

                                        if ($rv->{status} ne 'SPI_OK_UPDATE' || $rv->{processed} != 1)
                                        {
                                            $errmsg = "Bad update db statement: $stmnt.";
                                            elog(WARNING, $errmsg);
                                            $$statusR = 1;
                                        }
                                    }
                                    elsif ($maxrec < $recno)
                                    {
                                        # The current version of the DRMS record was deleted. Update both the nrecords column and the recnum column.
                                        # UPDATE <shadow> SET recnum = <maxrec>, nrecords = nrecords - 1 WHERE <pkey1>=<pkey1val> AND <pkey2>=<pkey2val> AND ...

                                        $stmnt = "UPDATE $shadow SET recnum = $maxrec, nrecords = nrecords - 1 WHERE $keylist";

                                        # Updating a single record.
                                        $rv = spi_exec_query($stmnt);

                                        if ($rv->{status} ne 'SPI_OK_UPDATE' || $rv->{processed} != 1)
                                        {
                                            $errmsg = "Bad update db statement: $stmnt.";
                                            elog(WARNING, $errmsg);
                                            $$statusR = 1;
                                        }
                                    }
                                    else
                                    {
                                        # Cannot happen - duplicate recnums are not allowed.
                                        $errmsg = "Was there a duplicate recnum? Impossible.";
                                        elog(WARNING, $errmsg);
                                        $$statusR = 1;
                                    }
                                }
                            }
                        };

    # INSERT INTO <shadow> (pkey1, pkey2, ..., kShadowColRecnum, kShadowColNrecs) SELECT pkey1, pkey2, ..., recnum, 1 FROM <series> WHERE recnum = <recnum>
    $fInsertIntoShadow = sub {
                                my($ns, $tab, $pkeynamesR, $recno, $statusR) = @_;
                                my($sname);
                                my($shadow);
                                my($stmnt);
                                my($keylist);
                                my($cleankey);
                                my($errmsg);
                                my($rv);

                                $sname = lc("$ns\.$tab");
                                $shadow = $sname . &kShadowSuffix;

                                $stmnt = "INSERT INTO $shadow (";

                                # Loop through prime-key keywords.
                                $keylist = "";
                                foreach my $key (@{$pkeynamesR})
                                {
                                    $cleankey = &{$fCleanKey}($key);
                                    $keylist = "$keylist$cleankey, ";
                                }

                                $stmnt = "${stmnt}${keylist}recnum, nrecords) SELECT ${keylist}recnum, 1 FROM $sname WHERE recnum = $recno";

                                # Inserting a single record.
                                $rv = spi_exec_query($stmnt);

                                if ($rv->{status} ne 'SPI_OK_INSERT' || $rv->{processed} != 1)
                                {
                                    $errmsg = "Bad db insert statement: $stmnt.";
                                    elog(ERROR, $errmsg);
                                    $$statusR = 1;
                                }
                            };

    # SELECT count(*) FROM <series> WHERE <pkey1> = <pkey1val> AND <pkey2> = <pkey2val> AND ...;
    $fWasGroupDeleted = sub {
                                my($ns, $tab, $pkeynamesR, $primekeyvalsH, $recno, $statusR) = @_;
                                my($sname);
                                my($stmnt);
                                my($ikey);
                                my($keylist);
                                my($cleankey);
                                my($errmsg);
                                my($rv);
                                my($wasdel);

                                $rv = -1;
                                $sname = lc("$ns\.$tab");

                                # Loop through prime-key keywords.
                                $ikey = 0;
                                $keylist = "";
                                foreach my $key (@{$pkeynamesR})
                                {
                                    $cleankey = &{$fCleanKey}($key);

                                    if ($ikey > 0)
                                    {
                                        $keylist = "$keylist AND ";
                                    }

                                    if ($key =~ /\*$/)
                                    {
                                        $keylist = "${keylist}$cleankey = \'" . $primekeyvalsH->{$cleankey} . "\'";
                                    }
                                    else
                                    {
                                        $keylist = "${keylist}$cleankey = " . $primekeyvalsH->{$cleankey};
                                    }

                                    $ikey++;
                                }

                                $stmnt = "SELECT count(*) FROM $sname WHERE $keylist";

                                $rv = spi_exec_query($stmnt, 1);
                                if ($rv->{status} eq 'SPI_OK_SELECT' && $rv->{processed} == 1)
                                {
                                    # The group was deleted if there are no more records
                                    $wasdel = ($rv->{rows}[0]->{count} == 0);
                                }
                                else
                                {
                                    $errmsg = "Bad select statement $stmnt";
                                    elog(WARNING, $errmsg);
                                    $$statusR = 1;
                                }

                                return $wasdel;
                            };

    # This function may be a no-op. This will happen if more than one record was deleted from the series
    # table, such that the last record deleted caused the deletion of a group, and a previous deletion
    # was in the same group. In that case, the first time the trigger function is called, the group record
    # will be deleted from the shadow table. This happens because all series records are deleted before
    # the trigger function is called (and then it is called for each series record that got deleted).
    # The second and subsequent calls of the trigger function will not result in the deletion of any records
    # from the shadow table, since the record has already been removed. For these calls, $rv->{processed} will
    # be 0 since the DELETE statement does not delete anything.
    #
    # DELETE FROM <shadow> WHERE <pkey1> = <pkey1val> AND <pkey2> = <pkey2val> ...*/
    $fDeleteFromShadow = sub {
                                my($ns, $tab, $pkeynamesR, $primekeyvalsH, $statusR) = @_;
                                my($sname);
                                my($shadow);
                                my($stmnt);
                                my($ikey);
                                my($keylist);
                                my($cleankey);
                                my($errmsg);
                                my($rv);

                                $rv = -1;
                                $sname = lc("$ns\.$tab");
                                $shadow = $sname . &kShadowSuffix;

                                # Loop through prime-key keywords.
                                $ikey = 0;
                                $keylist = "";
                                foreach my $key (@{$pkeynamesR})
                                {
                                    $cleankey = &{$fCleanKey}($key);

                                    if ($ikey > 0)
                                    {
                                        $keylist = "$keylist AND ";
                                    }

                                    if ($key =~ /\*$/)
                                    {
                                        $keylist = "${keylist}$cleankey = \'" . $primekeyvalsH->{$cleankey} . "\'";
                                    }
                                    else
                                    {
                                        $keylist = "${keylist}$cleankey = " . $primekeyvalsH->{$cleankey};
                                    }

                                    $ikey++;
                                }

                                $stmnt = "DELETE FROM $shadow WHERE $keylist";

                                $rv = spi_exec_query($stmnt);
                                # Will not delete any record if the record was previously deleted.
                                if ($rv->{status} ne 'SPI_OK_DELETE' || ($rv->{processed} != 1 && $rv->{processed} != 0))
                                {
                                    $errmsg = "Bad delete db statement: $stmnt.";
                                    elog(WARNING, $errmsg);
                                    $$statusR = 1;
                                }
                        };

    my($shadowexists);
    my($inserted);
    my($datarec); # This contains the string 'new' or 'old' - to refer to either the
                  # inserted (new) record, or the deleted (old) record where data record
                  # values are needed. If a record was inserted, then the data record
                  # values that are needed reside in the 'new' record. If a record was
                  # deleted, then the data record values that are needed reside in the 'old'
                  # record.
    my($recnum);
    my(@primekeys);
    my($cleankey);
    my($primekeyvalsH);
    my($isnew);
    my($wasdel);
    my($istat);

    # This function should be a no-op if there is no shadow table.
    $shadowexists = &{$fShadowExists}($_TD->{table_schema}, $_TD->{table_name}, \$istat);

    if ($istat)
    {
        elog(ERROR, "Cannot check for existence of shadow table.");
    }

    if ($shadowexists)
    {
        # Support row insertions and deletions only.
        if ($_TD->{event} eq 'INSERT')
        {
            $inserted = 1;
            $datarec = 'new';
        }
        elsif ($_TD->{event} eq 'DELETE')
        {
            $inserted = 0;
            $datarec = 'old';
        }
        else
        {
            elog(ERROR, "Unsupported trigger event " . $_TD->{event} . "\.");
        }

        # The record inserted is the 'new' record, and the record deleted is the 'old' record.
        $recnum = $_TD->{$datarec}{recnum};

        # Query dbase to get a list of prime-key keyword names.
        @primekeys = &{$fGetPkeys}($_TD->{table_schema}, $_TD->{table_name}, \$istat);

        if ($istat)
        {
            elog(ERROR, "Cannot obtain the names of the prime-key keywords.");
        }

        # Insert prime-key value into $primkeyvalsH.
        $primekeyvalsH = {};
        foreach my $pkey (@primekeys)
        {
            $cleankey = &{$fCleanKey}($pkey);
            $primekeyvalsH->{$cleankey} = $_TD->{$datarec}{$cleankey};
        }

        if ($inserted)
        {
            # We're updating the shadow table because one or more rows was inserted into the original series table.
            $isnew = &{$fIsGroupNew}($recnum, $_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $primekeyvalsH, \$istat);

            if ($istat)
            {
                elog(ERROR, "Failure in IsGroupNew().");
            }

            if ($isnew == 0)
            {
                # Need to update an existing record in the shadow table.
                &{$fUpdateShadow}($_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $primekeyvalsH, $recnum, 1, \$istat);

                if ($istat)
                {
                    elog(ERROR, "Failure calling UpdateShadow() for record insertion.");
                }
            }
            elsif ($isnew == 1)
            {
                # Need to add a new record to the shadow table for the new group just created in the series table.
                # shadow-table structure - pkey1, pkey2, ..., recnum, nrecords
                &{$fInsertIntoShadow}($_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $recnum, \$istat);

                if ($istat)
                {
                    elog(ERROR, "Failure in InsertIntoShadow().");
                }
            }
            else
            {
                # Unexpected value for isnew.
                elog(ERROR, "IsGroupNew() returned an unexpected value.");
            }
        }
        else
        {
            # We're updating the shadow table because one or more rows was deleted from the original series table.
            $wasdel = &{$fWasGroupDeleted}($_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $primekeyvalsH, $recnum, \$istat);

            if ($istat)
            {
                elog(ERROR, "Failure in WasGroupDeleted().");
            }

            if ($wasdel)
            {
                # The last DRMS record was deleted - delete the corresponding group from the shadow table.
                &{$fDeleteFromShadow}($_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $primekeyvalsH, \$istat);

                if ($istat)
                {
                    elog(ERROR, "Failure in DeleteFromShadow().");
                }
            }
            else
            {
                # One version of a DRMS record was deleted. May need to update the corresponding groups record in the shadow table (update nrecords and recnum). If the version deleted was an obsolete version, then no change to the recnum in the shadow table is needed.
                &{$fUpdateShadow}($_TD->{table_schema}, $_TD->{table_name}, \@primekeys, $primekeyvalsH, $recnum, 0, \$istat);

                if ($istat)
                {
                    elog(ERROR, "Failure calling UpdateShadow() for record deletion.");
                }
            }
        }
    }

    return;
$updateshadow$ LANGUAGE plperlu;

-- This script is a template; must substitute in the name of the table
-- CREATE TRIGGER updateshadowtrig AFTER INSERT OR DELETE on <TABLE>
--    FOR EACH ROW EXECUTE PROCEDURE updateshadow();
