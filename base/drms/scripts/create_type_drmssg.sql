create type drmssg as (
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