DROP TYPE IF EXISTS seginfo CASCADE;
CREATE TYPE seginfo AS 
(
    series varchar(64),
    segment varchar(32),
    datatype varchar(16),
    segnum int8,
    scope varchar(16),
    numaxes int8,
    dimensions varchar(32),
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
BEGIN
    -- origsegment is needed in the case that the caller provides NULL for datasegment (requesting information about all segments in a series)
    FOR linkmaprecord IN SELECT S.segment, S.linkedseries, S.linkedsegment FROM drms_linkedsegment(dataseries, datasegment) AS S LOOP
        origsegment := linkmaprecord.segment;
        linkedseries := linkmaprecord.linkedseries;
        linkedsegment := linkmaprecord.linkedsegment;

        LOOP
            raise notice '%', linkedseries;

            IF linkedseries IS NULL THEN
                -- not a linked series
                SELECT regexp_split_to_array(dataseries, E'\\.') INTO parsed;
                namespace := parsed[1];
                relation := parsed[2];
                -- return original series and segment name so the caller can locate the information by input values easily
                RETURN QUERY EXECUTE 'SELECT seriesname::varchar AS series, segmentname::varchar AS segment, type::varchar AS datatype, segnum::int8 AS segnum, scope::varchar, naxis::int8 AS numaxes, axis::varchar AS dimensions, unit::varchar, protocol::varchar, description FROM ' || quote_ident(namespace) || '.drms_segment WHERE lower(seriesname) = $1 AND lower(segmentname) = $2' USING lower(dataseries), lower(origsegment);
                EXIT;
            ELSE
                -- linked series
                raise notice 'link query %', 'SELECT ' || quote_literal(dataseries) || '::varchar AS series, ' || quote_literal(origsegment) || '::varchar AS segment, datatype, segnum, scope, numaxes, dimensions, unit, protocol, description FROM drms_followsegmentlink(' || quote_literal(linkedseries) || ',' || quote_literal(linkedsegment) || ')';
                RETURN QUERY EXECUTE 'SELECT ' || quote_literal(dataseries) || '::varchar AS series, ' || quote_literal(origsegment) || '::varchar AS segment, datatype, segnum, scope, numaxes, dimensions, unit, protocol, description FROM drms_followsegmentlink(' || quote_literal(linkedseries) || ',' || quote_literal(linkedsegment) || ')';
                EXIT;
            END IF;
        END LOOP;
    END LOOP;
    
END;
$$
LANGUAGE plpgsql;
