/**
\file drms_statuscodes.h
*/
#ifndef _DRMS_STATUSCODES_H
#define _DRMS_STATUSCODES_H


#define CHECKNULL(ptr)  if (!(ptr)) return DRMS_ERROR_NULLPOINTER
#define CHECKNULL_STAT(ptr,stat)   do {  \
                                      if (!(ptr)) { \
                                        if ((stat)) \
                                          *(stat) = DRMS_ERROR_NULLPOINTER; \
                                          fprintf(stderr,"ERROR at %s, line %d: "#ptr" = NULL.\n",__FILE__,__LINE__); \
                                        return NULL; \
                                      } \
                                   } while(0)
#define CHECKSNPRINTF(code, len) do {\
  if ((code) >= (len)) { \
    fprintf(stderr, "WARNING: string is truncated in %s, line %d\n",__FILE__,__LINE__); \
  }\
} while (0)


/* DRMS status codes */
/* Success. */
#define DRMS_NO_ERROR                   (0)
#define DRMS_SUCCESS                    (0)

/* Status codes for type conversion. */
#define DRMS_VALUE_MISSING     (-3)  /* Returned by getkey for unknown keyword. */
#define DRMS_BADSTRING   (-2)
#define DRMS_RANGE       (-1)
#define DRMS_EXACT        (0)  /* == DRMS_SUCCESS */
#define DRMS_INEXACT      (1)


/* Error codes. */
#define DRMS_ERROR_BADSEQUENCE      (-10001)
#define DRMS_ERROR_BADTEMPLATE      (-10002)
/**
\brief the  parameter specifying the series name refers to a non-existent series
*/
#define DRMS_ERROR_UNKNOWNSERIES    (-10003)
#define DRMS_ERROR_UNKNOWNRECORD    (-10004)
#define DRMS_ERROR_UNKNOWNLINK      (-10005)
#define DRMS_ERROR_UNKNOWNKEYWORD   (-10006)
#define DRMS_ERROR_UNKNOWNSEGMENT   (-10007)
#define DRMS_ERROR_BADFIELDCOUNT    (-10008) 
#define DRMS_ERROR_INVALIDLINKTYPE  (-10009)
#define DRMS_ERROR_BADLINK          (-10010)
#define DRMS_ERROR_UNKNOWNUNIT      (-10011)
#define DRMS_ERROR_QUERYFAILED      (-10012)
#define DRMS_ERROR_BADQUERYRESULT   (-10013)
#define DRMS_ERROR_UNKNOWNSU        (-10014)
#define DRMS_ERROR_RECORDREADONLY   (-10015)
#define DRMS_ERROR_KEYWORDREADONLY  (-10016)
#define DRMS_ERROR_NOTIMPLEMENTED   (-10017)
#define DRMS_ERROR_UNKNOWNPROTOCOL  (-10018)
#define DRMS_ERROR_NULLPOINTER      (-10019)
#define DRMS_ERROR_INVALIDTYPE      (-10020)
#define DRMS_ERROR_INVALIDDIMS      (-10021)
#define DRMS_ERROR_INVALIDACTION    (-10022)
#define DRMS_ERROR_COMMITREADONLY   (-10023)
#define DRMS_ERROR_SYNTAXERROR      (-10024)
#define DRMS_ERROR_BADRECORDCOUNT   (-10025)
#define DRMS_ERROR_NULLENV          (-10026)
/**
\brief a memory allocation fails due to insufficient memory available
*/
#define DRMS_ERROR_OUTOFMEMORY      (-10027)
#define DRMS_ERROR_UNKNOWNCOMPMETH  (-10028)
#define DRMS_ERROR_COMPRESSFAILED   (-10029)
#define DRMS_ERROR_INVALIDRANK      (-10030)
#define DRMS_ERROR_MKDIRFAILED      (-10031)
#define DRMS_ERROR_UNLINKFAILED     (-10032)
#define DRMS_ERROR_STATFAILED       (-10033)
#define DRMS_ERROR_SUMOPEN          (-10034)
#define DRMS_ERROR_SUMPUT           (-10035)
#define DRMS_ERROR_SUMGET           (-10036)
#define DRMS_ERROR_SUMALLOC         (-10037)
#define DRMS_ERROR_SUMWAIT          (-10038)
#define DRMS_ERROR_SUMBADOPCODE     (-10039)
#define DRMS_ERROR_INVALIDFILE      (-10040)
#define DRMS_ERROR_IOERROR          (-10041)
#define DRMS_ERROR_LINKNOTSET       (-10042)
#define DRMS_ERROR_BADJSD           (-10043)
#define DRMS_ERROR_INVALIDRECORD    (-10044)
#define DRMS_ERROR_INVALIDKEYWORD   (-10045)
#define DRMS_ERROR_INVALIDSEGMENT   (-10046)
#define DRMS_ERROR_INVALIDLINK      (-10047)
/**
\brief a parameter to a function has an unexpected value (such as providing a null pointer when a character string is expected) 
*/
#define DRMS_ERROR_INVALIDDATA      (-10048) /* Bad parameters to a drms function call. */
#define DRMS_ERROR_NODSDSSUPPORT    (-10049)
#define DRMS_ERROR_LIBDSDS          (-10050)
#define DRMS_ERROR_ABORT            (-10051)
#define DRMS_ERROR_CANTOPENLIBRARY  (-10052)
#define DRMS_ERROR_INVALIDRECSCOPETYPE  (-10053)
#define DRMS_ERROR_CANTCREATEHCON   (-10054)
#define DRMS_ERROR_EXPORT           (-10055)
#define DRMS_ERROR_FITSRW           (-10056)
#define DRMS_ERROR_CANTCREATERECORD (-10057)
#define DRMS_ERROR_BADCHUNKSIZE     (-10058)
#define DRMS_ERROR_RECSETCHUNKRANGE (-10059)
#define DRMS_ERROR_SEGMENT_DATA_MISMATCH  (-10060)
#define DRMS_ERROR_ARRAYCREATEFAILED      (-10061)
#define DRMS_ERROR_CANTCREATETASFILE      (-10062)
#define DRMS_ERROR_DSDSOFFLINE      (-10063)
#define DRMS_ERROR_UNKNOWNCMDARG    (-10064)
#define DRMS_ERROR_INVALIDCMDARGCONV      (-10065)
#define DRMS_ERROR_RECORDSETSUBSET  (-10066)
#define DRMS_ERROR_NOSEGMENT        (-10067)
#define DRMS_ERROR_RESERVEDFITSKW   (-10069)
#define DRMS_ERROR_FILECOPY         (-10070)
#define DRMS_ERROR_FILECREATE       (-10071)
#define DRMS_ERROR_SUMDELETESERIES  (-10072)
#define DRMS_ERROR_NOSTORAGEUNIT    (-10073)
#define DRMS_ERROR_INVALIDSU        (-10074)
#define DRMS_ERROR_BADDBQUERY       (-10075)

#define DRMS_ERROR_SUMINFO          (-10075)
#define DRMS_ERROR_NEEDSUMS         (-10076)

#define DRMS_ERROR_CANTCREATESHADOW (-10077)

#define DRMS_ERROR_UNKNOWNSHADOW    (-10078)
#define DRMS_ERROR_SEGMENTWRITE     (-10079)
#define DRMS_ERROR_CANTCONNECTTODB  (-10080)
#define DRMS_ERROR_CANTCOMPRESSFLOAT      (-10081)
#define DRMS_ERROR_SUMSTRYLATER     (-10082)
#define DRMS_ERROR_CANTMODPUBSERIES (-10083)
#define DRMS_ERROR_PENDINGTAPEREAD  (-10084)
#define DRMS_ERROR_INVALIDSCALING   (-10085)
#define DRMS_ERROR_OVERFLOW         (-10086)
#define DRMS_ERROR_SHADOWTAB        (-10089)
#define DRMS_ERROR_DATASTRUCT       (-10090)
#define DRMS_ERROR_CANTCREATETHREAD (-10091)
#define DRMS_ERROR_MODDBTRANS       (-10092)

/* remote sums */
#define DRMS_REMOTESUMS_TRYLATER                (-30000)
#define DRMS_ERROR_REMOTESUMS_MISSING           (-30001)
#define DRMS_ERROR_REMOTESUMS_INVALIDSUNUM      (-30002)
#define DRMS_ERROR_REMOTESUMS_REQUEST           (-30003)
#define DRMS_ERROR_REMOTESUMS_INITIALIZATION    (-30004)

/* Warnings */
#define DRMS_WARNING_BADBLANK         (10000)
#define DRMS_QUERY_TRUNCATED          (10001)
#endif


