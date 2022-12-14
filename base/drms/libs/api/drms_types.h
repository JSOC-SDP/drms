/**
\file drms_types.h
*/
#ifndef _DRMS_TYPES_H
#define _DRMS_TYPES_H

#include <math.h>
#include <float.h>
#include <limits.h>
#include <stdint.h>
#include "db.h"
#include "hcontainer.h"
#include "list.h"
#include "util.h"
#include "tagfifo.h"
#include "timeio.h"
#include "SUM.h"
#include "serverdefs.h"
#include "sum_rpc.h"

/* Constants */
#define DRMS_MAXNAMELEN        (32)
#define DRMS_MAXSERIESNAMELEN  (64)
#define DRMS_MAXOWNERLEN       DRMS_MAXNAMELEN
#define DRMS_MAXSERIESVERSION  (64)
#define DRMS_MAXKEYNAMELEN     DRMS_MAXNAMELEN
#define DRMS_MAXLINKNAMELEN    DRMS_MAXNAMELEN
#define DRMS_MAXSEGNAMELEN     DRMS_MAXNAMELEN
#define DRMS_MAXCURSORNAMELEN  (64) /* by default, postgres identifiers are 63 bytes max */
/** \brief Maximum DRMS hash byte length */
#define DRMS_MAXHASHKEYLEN     (DRMS_MAXSERIESNAMELEN+22)
/** \brief Maximum byte length of unit string */
#define DRMS_MAXUNITLEN        (32)
#define DRMS_MAXQUERYLEN       (8192)
#define DRMS_MAXBIGQUERYLEN    (16384)
#define DRMS_MAXPATHLEN        (512)
#define DRMS_MAXFORMATLEN      (20)
/** \brief Maximum dimension of DRMS data */
#define DRMS_MAXRANK           (16)
/** \brief Maximum number of DRMS segments per record */
#define DRMS_MAXSEGMENTS       (255)
/** \brief Maximum DRMS comment byte length */
#define DRMS_MAXCOMMENTLEN     (255)
/** \brief Maximum byte length of DRMS segment file name */
#define DRMS_MAXSEGFILENAME    (256)
/** \brief Maximum byte length of a segment's compression-parameter string */
#define DRMS_MAXCPARMS         (256)
/** \brief Max number of keywords in the primary index. */
#define DRMS_MAXPRIMIDX        (15)
/** \brief Max number of keywords to make db index. */
#define DRMS_MAXDBIDX          (10)
/** \brief Max length of the string holding a keyword default value. */
#define DRMS_DEFVAL_MAXLEN     (1000)
/** \brief The maximal length we allow of a chain of links. If a chain
longer than this is encountered we assume that there is a cyclic
link. */
#define DRMS_MAXLINKDEPTH  (20)
#define DRMS_MAXHOSTNAME (128)

/** \brief Maximum number of in-memory records - 16MB for now */
#define DRMS_MAXCHUNKSIZE      (16777216)

#include "drms_protocol.h"

/*************************** DRMS related types ************************/


/************************ Simple data types **********************/

/* Values of keywords belong to one of the following simple classes.
 * RAW is not really a type, but is used when reading segment data
   to indicate that the data should be read in without and type
   conversino or scaling. */
/**
   @brief DRMS Data types
 */
typedef enum {
   /** \brief DRMS char type */
   DRMS_TYPE_CHAR,
   /** \brief DRMS short type */
   DRMS_TYPE_SHORT,
   /** \brief DRMS int type */
   DRMS_TYPE_INT,
   /** \brief DRMS longlong type */
   DRMS_TYPE_LONGLONG,
   /** \brief DRMS float type */
   DRMS_TYPE_FLOAT,
   /** \brief DRMS double type */
   DRMS_TYPE_DOUBLE,
   /** \brief DRMS time type */
   DRMS_TYPE_TIME,
   /** \brief DRMS string type */
   DRMS_TYPE_STRING,
   /** \brief DRMS raw type */
   DRMS_TYPE_RAW
} DRMS_Type_t;

#ifndef DRMS_TYPES_C
extern char *drms_type_names[];
#else
/**
   \brief Strings describing the supported DRMS types
   \sa ::DRMS_Type_t
*/
char *drms_type_names[] = {"char", "short", "int", "longlong",
			   "float", "double", "time", "string", "raw"};
#endif

/** \brief DRMS type value */
union DRMS_Type_Value
{
  char char_val;
  short short_val;
  int   int_val;
  long long longlong_val;
  float float_val;
  double double_val;
  double time_val;
  char *string_val;
};

/** \brief DRMS type value reference */
typedef union DRMS_Type_Value DRMS_Type_Value_t;

/* DRMS_Type_Value_t is fine as long as you know the type.  But we also need a construct
 * that is useful in generic code (type-unaware), for example, using the results of
 * drms_getkey() in a call to drms_setkey().
 */
typedef struct DRMS_Value
{
  DRMS_Type_t type;
  DRMS_Type_Value_t value;
} DRMS_Value_t;

/* Default "missing" values for standard types. */
/** \brief DRMS char missing value */
#define DRMS_MISSING_CHAR     (SCHAR_MIN)
/** \brief DRMS short missing value */
#define DRMS_MISSING_SHORT    (SHRT_MIN)
/** \brief DRMS int missing value */
#define DRMS_MISSING_INT      (INT_MIN)
/** \brief DRMS longlong missing value */
#define DRMS_MISSING_LONGLONG (LLONG_MIN)
/** \brief DRMS float missing value */
#define DRMS_MISSING_FLOAT    (F_NAN)
#define _DRMS_IS_F_MISSING(v) (isnan(v))
/** \brief DRMS double missing value */
#define DRMS_MISSING_DOUBLE   (D_NAN)
#define _DRMS_IS_D_MISSING(v) (isnan(v))
/** \brief DRMS C string missing value */
#define DRMS_MISSING_STRING   ("")
/** \brief DRMS time missing value */
#define DRMS_MISSING_TIME     (-211087684832.184)
/* equal to '-4712.01.01_12:00:00.000_TDT' which is the time value used
   missing in the MDI/SDS system. */
/* Truncate the fractional seconds during comparison because .jsds that have time keywords whose
 * format fields are '0' will yield time strings that are integral */
#define _DRMS_IS_T_MISSING(v) (isnan(v) || ((long long)v < (long long)DRMS_MISSING_TIME + 10.0e-5 && (long long)v > (long long)DRMS_MISSING_TIME - 10.0e-5))

#define TSEQ_EPOCH_S MDI_EPOCH_S
#define TSEQ_EPOCH_F MDI_EPOCH_F
#define TSEQ_EPOCH MDI_EPOCH
#define SDO_EPOCH_S "1958.01.01_00:00:00_TAI"
#define SDO_EPOCH_F (sscan_time (SDO_EPOCH_S))
#define SDO_EPOCH (-599616000.000)

#define DRMS_MAXTYPENAMELEN  (9)


/* */
#ifdef ICCCOMP
#pragma warning (disable : 1572)
#endif
static inline int drms_ismissing_char(char value)
{
   return (DRMS_MISSING_CHAR == value);
}

static inline int drms_ismissing_short(short value)
{
   return (DRMS_MISSING_SHORT == value);
}

static inline int drms_ismissing_int(int value)
{
   return (DRMS_MISSING_INT == value);
}

static inline int drms_ismissing_longlong(long long value)
{
   return (DRMS_MISSING_LONGLONG == value);
}

static inline int drms_ismissing_float(float value)
{
   return (_DRMS_IS_F_MISSING(value));
}

static inline int drms_ismissing_double(double value)
{
   return (_DRMS_IS_D_MISSING(value));
}

static inline int drms_ismissing_time(TIME value)
{
   return (_DRMS_IS_T_MISSING(value));
}

static inline int drms_ismissing_string(char *value)
{
   return (!value || *value == '\0');
}

static inline int drms_ismissing(DRMS_Value_t *val)
{
    int ans = -1;

    switch(val->type)
    {
        case DRMS_TYPE_CHAR:
            ans = drms_ismissing_char(val->value.char_val);
            break;
        case DRMS_TYPE_SHORT:
            ans = drms_ismissing_short(val->value.short_val);
            break;
        case DRMS_TYPE_INT:
            ans = drms_ismissing_int(val->value.int_val);
            break;
        case DRMS_TYPE_LONGLONG:
            ans = drms_ismissing_longlong(val->value.longlong_val);
            break;
        case DRMS_TYPE_FLOAT:
            ans = drms_ismissing_float(val->value.float_val);
            break;
        case DRMS_TYPE_TIME:
            ans = drms_ismissing_time(val->value.time_val);
            break;
        case DRMS_TYPE_DOUBLE:
            ans = drms_ismissing_double(val->value.double_val);
            break;
        case DRMS_TYPE_STRING:
            ans = drms_ismissing_string(val->value.string_val);
            break;
        default:
            fprintf(stderr, "Unsupported data type %d.\n", (int)val->type);
    }

    return ans;
}

static inline int drms_ismissing2(DRMS_Type_t type, DRMS_Type_Value_t *val)
{
    int ans = -1;

    switch(type)
    {
        case DRMS_TYPE_CHAR:
            ans = drms_ismissing_char(val->char_val);
            break;
        case DRMS_TYPE_SHORT:
            ans = drms_ismissing_short(val->short_val);
            break;
        case DRMS_TYPE_INT:
            ans = drms_ismissing_int(val->int_val);
            break;
        case DRMS_TYPE_LONGLONG:
            ans = drms_ismissing_longlong(val->longlong_val);
            break;
        case DRMS_TYPE_FLOAT:
            ans = drms_ismissing_float(val->float_val);
            break;
        case DRMS_TYPE_TIME:
            ans = drms_ismissing_time(val->time_val);
            break;
        case DRMS_TYPE_DOUBLE:
            ans = drms_ismissing_double(val->double_val);
            break;
        case DRMS_TYPE_STRING:
            ans = drms_ismissing_string(val->string_val);
            break;
        default:
            fprintf(stderr, "Unsupported data type %d.\n", (int)type);
    }

    return ans;
}

#ifdef ICCCOMP
#pragma warning (default : 1572)
#endif

/****************************** DRMS Environment ***************************/


/******** Internal server data types. ********/


/* Database or DRMS client connection info. */
/** \brief DRMS Session struct */
struct DRMS_Session_struct
{
  int db_direct;    /* If db_direct == 1 then go directly to the DB
		       without passing calls through a DRMS server. */

  /******** server database connection for db_direct==1 ***********/
  DB_Handle_t *db_handle; /* Main database connection used for DRMS data.
			     This connection runs a single serializable
			     transaction for the entire session. */
  DB_Handle_t *stat_conn; /* Extra database connection. Only used by the
			     DRMS server to update its status info
			     in drms_session_table. */

  /* Unique session id. */
  long long sessionid;
  /* Session namespace */
  char *sessionns;

  /* sunum and directory of the storage unit holding the session
     log files.  */
  long long sunum;   /*  = sunum for the storage unit. */
  char *sudir; /* = storage unit directory for log files etc. */

  /* Client id. Used by clients to uniqely identify themselves within
     a session. */
  int clientid;

  /**** client DRMS connection for db_direct==0 *******/
  char hostname[DRMS_MAXHOSTNAME]; /* host on which drms_server is running. */
  unsigned short port;             /* port on drms_server host to which client is connected. */
  int sockfd;
  int readonly; /* When a session starts, it will be readonly (readonly == 1). If a user wants to write to the db,
                 * then readonly is set to 0. */
  char startTime[32]; /* A time string that indicates when the session was opened. Needed for the session-log record, should one
                       * get written. */

    /* DB-connection information (from drms_server to the database). */
    char dbhost[DRMS_MAXHOSTNAME];
    int dbport;
    char dbname[64];
    char dbuser[64];
};

/** DRMS session struct reference */
typedef struct DRMS_Session_struct DRMS_Session_t;

/* Link list node for keeping track of temporary records in the server.
   quick UGLY  hack. */
typedef struct DS_node_struct
{
  char *series;
  int n,nmax;
  long long *recnums;
  struct DS_node_struct *next;
} DS_node_t;

enum DRMS_Shutdown_State_enum
{
   kSHUTDOWN_UNINITIATED = 0,
   kSHUTDOWN_COMMITINITIATED = 1, /* DoIt() hasn't been notified that a shutdown is happening */
   kSHUTDOWN_ABORTINITIATED = 2,  /* DoIt() hasn't been notified that a shutdown is happening */
   kSHUTDOWN_COMMIT = 3,          /* DoIt() has been notified */
   kSHUTDOWN_ABORT = 4,           /* DoIt() has been notified */
   kSHUTDOWN_BYMAIN = 5           /* Main is shutting down (not signal thread) */
};

typedef enum DRMS_Shutdown_State_enum DRMS_Shutdown_State_t;

typedef int (*pFn_Cleaner_t)(void *);

struct CleanerData_struct
{
  pFn_Cleaner_t cb; /* Callback to be invoked at shutdown. */
  void *data; /* Argument to callback function */
};

typedef struct CleanerData_struct CleanerData_t;

/** \brief DRMS environment struct */
struct DRMS_Env_struct
{
  DRMS_Session_t *session;     /* Database connection handle or socket
				  connection to DRMS server. */
  HContainer_t series_cache;   /* Series cache data structures. */
  HContainer_t record_cache;   /* Record cache data structures. */
  HContainer_t storageunit_cache; /* Storage unit cache. */
  DS_node_t *templist; /* List of temporary records created for each series
			by this session. */

  int16_t retention; /* retention in days. If not -1 then this value overrides
		   the retention time for storage units accessed during this
		   session. Server only. */
  int query_mem; /* Maximum amount of memory (in MB) used by a single record
		    query. */
  /* Server data. */
  int archive;     /* If archive=1, then archive all SU (including log SU) */
  int server_wait; /* If server_wait=1 then sleep DRMS_ABORT_SLEEP
		      seconds before freeing env. This suposely gives
    		      threads a small window to finish cleanly.
		      If server_wait=0, then free env immediately.
		      This is primarily used by drms_run script and
		      drms_server that starts from within a module */

  /* if verbose != 0, then print out many diagnostic messages */
  int verbose;

  char *dbpasswd;
  char *user;
  const char *logfile_prefix;
  int dolog;
  int quiet;

  int clientcounter;
  pid_t tee_pid;

  pthread_mutex_t *drms_lock; /* To synchronize the environment (which can be accessed/
                               * modified by signal thread, sums thread, and main thread during shutdown) */
  pthread_mutex_t *clientlock; /* To synchronize between server threads (one per client connected to
                                * drms_server). The policy is to allow only one client at a time
                                * inside drms_server's DRMS library. */

  /* SUM service thread. */
  pthread_t sum_thread;
  /* Tagged FIFOs for communicating with the SUM service thread. */
  tqueue_t *sum_inbox;
  tqueue_t *sum_outbox;
  long sum_tag; // tag of the request currently being served.

  /* Signal catching thread: */
  pthread_t signal_thread;
  sigset_t signal_mask;
  sigset_t old_signal_mask;

  /* For shutting down */
  pthread_t main_thread;
  int selfstart; /* if this is a drms_server environment, was drms_server self-started by a socket module */
  int transinit; /* First call to drms_server_begin_transaction() sets this to 1 after the env has been initialized
                  * drms_free_env() sets this to 0 after the env has been destroyed. */
  LinkedList_t *cleaners; /* A list of CleanerData_ts. Each node will invoke one function that
                           * takes one data struct as an argument. These functions will be
                           * called when the signal thread is about to terminate the DRMS
                           * module. */
  int transrunning; /* 1 if a transaction has been started by db_start_transaction() (set by
                     * drms_server_begin_transaction()); 0 otherwise (set by drms_server_end_transaction()) */
  int sessionrunning; /* 1 if a DRMS session has been started by drms_server_open_session() (set by
                       * drms_server_begin_transaction()); 0 otherwise (set by drms_server_end_transaction()) */
  int loopconn;
  int dbtimeout; /* DB queries running longer than this number milliseconds will be terminated.
                    * By default this is INT_MIN, which implies no timeout. */
  int16_t newsuretention; /* The retention time from the JSD, possibly overridden with the DRMS_NEWSURETENTION command-line argument. */
  int sumssafe; /* If 0, then don't call sums because DRMS timed-out waiting for SUMS. */
  int createshadows;  /* 1 if it is okay for module code to attempt to create shadow tables. */
  int dbutf8clientencoding;
  int print_sql_only; /* if 1, then the SQL used to retrieve DRMS records is printed, and then program execution ends */
};

/** \brief DRMS environment struct reference */
typedef struct DRMS_Env_struct DRMS_Env_t;

typedef struct DRMS_ThreadInfo_struct
{
  DRMS_Env_t *env;
  int noshare; /* If 1: Commit (rollback) and start new transaction
		  every time a client disconnects successfully
		  (unsuccessfully). This way we will release locks on tables
		  after every disconnect, and other database clients can get
		  through. */
  int threadnum;
  int sockfd;
} DRMS_ThreadInfo_t;


/*** SUMS server thread definitions. ***/

#define DRMS_SUMALLOC  0
#define DRMS_SUMGET    1
#define DRMS_SUMPUT    2
#define DRMS_SUMCLOSE  3
#define DRMS_SUMDELETESERIES 4
#define DRMS_SUMALLOC2  5
#define DRMS_SUMEXPORT  6 /* OBSOLETE - the implementation has been removed */
#define DRMS_SUMINFO    7
#define DRMS_SUMOPEN    8
#define DRMS_SUMABORT 99
#define DRMS_MAX_REQCNT MAXSUMREQCNT

/* Struct used for communication between service threads and
 * the SUMS communication thread.
 *
 * Note: When this structure is used as a request to SUMS, the
 * request is only shallow-freed from within the sums thread
 * main loop. It is the requestor's responsiblity
 * to free any memory allocated for the dsname, comment, and sudir fields.
 * When used as a reply, it is the requestor's responsibility
 * to free all memory associated with the reply, including
 * the structure itself.
 */
typedef struct DRMS_SumRequest_struct
{
  int opcode; /* Used for command code in inbox and status in the outbox. */

  int reqcnt;
  double bytes;
  char *dsname;
  int mode;
  int group;
  int tdays;
  char *comment;

  char *sudir[DRMS_MAX_REQCNT];
  uint64_t sunum[DRMS_MAX_REQCNT];

  int dontwait;
} DRMS_SumRequest_t;

#if defined(SUMS_USEMTSUMS) && SUMS_USEMTSUMS
/* Why oh why did he make a fixed array for sudir and sunum?
 */
typedef struct DRMS_MtSumsRequest_struct
{
  int opcode; /* Used for command code in inbox and status in the outbox. */

  int reqcnt;
  double bytes;
  char *dsname;
  int mode;
  int group;
  int tdays;
  char *comment;

  char **sudir;
  uint64_t *sunum;

  int dontwait;
} DRMS_MtSumsRequest_t;
#endif


/*************************** Data records and Series ************************/


/* Constants used to indicate lifetime of records created with
   drms_create_record(s) and drms_clone_record(s).
   DRMS_TEMPORARY means that the records will only exist in the
   database until the end of the DRMS session in which they
   were created.
*/
typedef enum {DRMS_PERMANENT, DRMS_TRANSIENT} DRMS_RecLifetime_t;

/** \brief DRMS cursor seek */
enum DRMS_RecSetCursorSeek_enum
{
   kRSChunk_First = 0,
   kRSChunk_Last,
   kRSChunk_Abs,
   kRSChunk_Next,
   kRSChunk_Prev
};

typedef enum DRMS_RecSetCursorSeek_enum DRMS_RecSetCursorSeek_t;

/** \brief DRMS cursor struct */
struct DRMS_RecSetCursor_struct
{
  /** \brief Parent recordset */
  struct DRMS_RecordSet_struct *parent;
  /** \brief Array of cursor names recognized by database query */
  char **names;
  /** \brief DRMS session environment - needed for querying db for next chunk */
  DRMS_Env_t *env;
  /** \brief Chunk size */
  int chunksize;
  /** \brief The index of the chunk currently loaded in the record-set */
  /* If this is -1, then there are no chunks in memory */
  int currentchunk;
  /** \brief If -1, then there are more PG records to fetch, if >= 0, then the value
   * is the index of the last record-set record in the current chunk. */

  /** \brief If 1, then attempt to fetch first record has occurred. */
  int iteration_started;

  int lastrec;
  /** \brief The relative index of the current record in the downloaded chunk 0 <= currentrec <= chunksize */
  int currentrec;
  /** \brief For each record-set query, 1 means there was a [! ... !] query */
  int *allvers;
  /** \brief For each record-set 1 means drms_stage_records has been called. */
  int staging_needed;
  /** \brief For needed staging, use this retrieve. */
  int retrieve;
  /** \brief For needed staging, use this dontwait. */
  int dontwait;

  int infoneeded;
  /** \brief The SUM_info_t *, keyed by sunum, needed when opening record chunks. */
  HContainer_t *suinfo;

  int openLinks; /* set in drms_open_recordset_internal(); passed into drms_open_recordset_internal() by client (e.g., show_info) */

  int cache_full_record; /* set in drms_open_recordset_internal(); passed into drms_open_recordset_internal() by client (e.g., show_info) */
};

/** \brief DRMS cursor struct reference */
typedef struct DRMS_RecSetCursor_struct DRMS_RecSetCursor_t;

typedef enum DRMS_RecordSetType_struct
{
   kRecordSetType_DRMS = 0,
   kRecordSetType_DSDS,
   kRecordSetType_VOT,
   kRecordSetType_PlainFile,
   kRecordSetType_DSDSPort
} DRMS_RecordSetType_t;

#ifndef DRMS_TYPES_C
    extern char *drms_type_recsetnames[];
#else
    char *drms_type_recsetnames[] =
    {
       "drms",
       "dsds",
       "vot",
       "plainfile",
       "dsdsport"
    };
#endif

/** \brief DRMS-Record-set container */
struct DRMS_RecordSet_struct
{
  /** \brief Number of records in the set */
  int n;
  /** \brief The set of records */
  struct DRMS_Record_struct **records;
  /** \brief The number of subsets in the set */
  int ss_n;
  /** \brief The queries that generated the subsets */
  char **ss_queries;
  /** \brief The query types */
  DRMS_RecordSetType_t *ss_types;
  /** \brief Array of offsets to the beginning of each subset */
  int *ss_starts;
  /** \brief Index (relative to first item in entire record set) of current record; used by code that iterates over records */
  int current_record; /* for cursored record sets, this can be > chunk_size -1 since it is the index into ALL records over ALL chunks */
  /** \brief DRMS record-set cursor - essentially a pointer into the return set of database records */
  /* NULL cursor means that this record-set is NOT chunked. */
  DRMS_RecSetCursor_t *cursor;
  /** \brief The environment in which this record-set was created. */
  DRMS_Env_t *env;

  HContainer_t **ss_template_keys;

  HContainer_t **ss_template_segs;

  LinkedList_t *linked_records_list;
  /** \brief a list of all records located by following links; set when the set's records are retrieved */
};

/** \brief DRMS record struct reference */
typedef struct DRMS_RecordSet_struct DRMS_RecordSet_t;

struct DRMS_SeriesVersion_struct
{
  char first[DRMS_MAXSERIESVERSION];
  char last[DRMS_MAXSERIESVERSION];
};

typedef struct DRMS_SeriesVersion_struct DRMS_SeriesVersion_t;

/* Series-wide attributes. */
typedef struct DRMS_SeriesInfo_struct
{
  char seriesname[DRMS_MAXSERIESNAMELEN];
  char description[DRMS_MAXCOMMENTLEN];
  char author[DRMS_MAXCOMMENTLEN];
  char owner[DRMS_MAXOWNERLEN];  /* Who is allowed to modify the series
				  definition. FIXME: WE PROBABLY NEED
				  PERMISSIONS TO INSERT NEW RECORDS. WE DON;T
				  WANT CASUAL USERS ACCIDENTALLY INSERTING
				  BOGUS DATA IN THE WRONG SERIES. */
  int unitsize;   /* How many records to a storage unit. */
  int archive;    /* Should this series be archived? */
  int retention;  /* Default retention time in seconds. */
  int retention_perm; /* Do I have permission to change retention? */
  int tapegroup;  /* Tapegroup of the series. */

  /* Prime key information. */
  int pidx_num;   /* Number of keywords in primary index. */
  struct DRMS_Keyword_struct *pidx_keywords[DRMS_MAXPRIMIDX];
                /* Pointers to keyword structs for keywords that
		   make up the primary key.*/
  /* DB index information. */
  int dbidx_num;   /* Number of keywords to make db index. */
  struct DRMS_Keyword_struct *dbidx_keywords[DRMS_MAXDBIDX];
  char version[DRMS_MAXSERIESVERSION];
    int createshadow; /* The jsd contained a line requesting that the shadow be created.
                       * Used only when running create_series on a jsd. */
    int hasshadow; /* -1: don't know, 0: no, 1: yes. */
}  DRMS_SeriesInfo_t;



/* Datastructure representing a single data record. */
/** \brief DRMS record struct */
struct DRMS_Record_struct
{
  struct DRMS_Env_struct *env;  /* Pointer to global DRMS environment. */

  long long recnum;                  /*** Unique record identifier. ***/
  long long sunum;                   /* Unique index of the storage unit associated
	        		   with this record. */

  int init;                    /* Flag used internally by the series cache. */
  int readonly;                /* Flag indicating if record is read-only. */
  DRMS_RecLifetime_t lifetime; /* Flag indicating if record is session-
				  temporary or permanent. */
  struct DRMS_StorageUnit_struct *su; /* Holds sudir (Storage unit directory).
				  	 Until the storage unit has been
				 	 requested from SUMS this pointer is
					 NULL. */
  int slotnum;          /* Number of the slot assigned within storage unit. */

  long long sessionid;       /* ID of the session that created this record. */
  char *sessionns;    /* namespace of the session that created this record. */

  DRMS_SeriesInfo_t *seriesinfo; /* Series to which this record belongs. */
  HContainer_t keywords;        /* Container of named keywords. */
  HContainer_t links;           /* Container of named links. */
  HContainer_t segments;        /* Container of named data segments. */
  SUM_info_t *suinfo; /* The structure returned by the SUM_infoEx() call.
                         Contains lots of storage-unit information. Can't
                         combine with su since su gets filled in by the SUM_get()
                         call. */
  int refcount; /* Track all references to the record struct in the
                       * record_cache. */
  HContainer_t *keyword_aliases; /* Each keyword can have an arbitrary number of aliases
                                  * (as long as there are no duplicate key names)
                                  */
};

/** DRMS record struct reference */
typedef struct DRMS_Record_struct DRMS_Record_t;

/**************************** Keywords ***************************/
#define kRecScopeIndex_B 100
#define kRecScopeSlotted_B 1000

/* Ancillary keys */
#define kSlotAncKey_Index "_index"
#define kSlotAncKey_Epoch "_epoch"
#define kSlotAncKey_Base "_base"
#define kSlotAncKey_Step "_step"
#define kSlotAncKey_Unit "_unit"
#define kSlotAncKey_Base "_base"
#define kSlotAncKey_Vals "_vals"
#define kSlotAncKey_Round "_round"

extern const DRMS_Type_t kIndexKWType;
extern const char *kIndexKWFormat;

enum DRMS_ExportKeyword_enum
{
   kExport_ReqID = 0,
   kExport_Request,
   kExport_SegList,
   kExport_Requestor,
   kExport_Notification,
   kExport_ReqTime,
   kExport_ExpTime,
   kExport_DataSize,
   kExport_Format,
   kExport_FileNameFormat,
   kExport_Status
};

typedef enum DRMS_ExportKeyword_enum DRMS_ExportKeyword_t;

struct ExportStrings_struct
{
  DRMS_ExportKeyword_t kw;
  const char *str;
};

typedef struct ExportStrings_struct ExportStrings_t;

extern ExportStrings_t gExpStr[];

enum DRMS_SlotKeyUnit_enum
{
   /** */
   kSlotKeyUnit_Invalid = 0,
   kSlotKeyUnit_TSeconds,
   kSlotKeyUnit_Seconds,
   kSlotKeyUnit_Minutes,
   kSlotKeyUnit_Hours,
   kSlotKeyUnit_Days,
   kSlotKeyUnit_Degrees,
   kSlotKeyUnit_Arcminutes,
   kSlotKeyUnit_Arcseconds,
   kSlotKeyUnit_MAS,
   kSlotKeyUnit_Radians,
   kSlotKeyUnit_MicroRadians
};

typedef enum DRMS_SlotKeyUnit_enum DRMS_SlotKeyUnit_t;

enum DRMS_TimeEpoch_enum
{
   /** */
   kTimeEpoch_Invalid = -1,
   kTimeEpoch_DRMS,
   kTimeEpoch_MDI,
   kTimeEpoch_WSO,
   kTimeEpoch_TAI,
   kTimeEpoch_MJD,
   kTimeEpoch_TSEQ,
   kTimeEpoch_END
};

typedef enum DRMS_TimeEpoch_enum DRMS_TimeEpoch_t;

enum DRMS_RecScopeType_enum
{
   /** \brief Plain vanilla variable across records. */
   kRecScopeType_Variable = 0,
   /** \brief Keyword is constant across records. */
   kRecScopeType_Constant = 1,
   /** \brief This value is reserved for 'Index' keywords.  An index keyword
    *  is one whose per-record values are the integers 'nearest' to the real
    *  number values of the corresponding non-index keyword.  If an index keyword
    *  is named TOBS_index, then the corresponding non-index keyword is TOBS. */
   kRecScopeType_Index = kRecScopeIndex_B,
   /** \brief A real-number keyword whose values are 'slotted'.
    *  If TOBS_index is an index keyword, and if TOBS is the corresponding
    *  TS_EQ-slotted keyword, TOBS has this slottype. */
   kRecScopeType_TS_EQ = kRecScopeSlotted_B,
   kRecScopeType_SLOT = kRecScopeSlotted_B + 1,
   kRecScopeType_ENUM = kRecScopeSlotted_B + 2,
   kRecScopeType_CARR = kRecScopeSlotted_B + 3,
   kRecScopeType_TS_SLOT = kRecScopeSlotted_B + 4

};

typedef enum DRMS_RecScopeType_enum DRMS_RecScopeType_t;

/* \brief DRMS Primary key type
   From the DRMS module perspective (external to DRMS),
   slotted keywords are DRMS prime.
   However, within DRMS, they are not. Each one is a non-prime key
   linked to an associated index keyword that IS DRMS prime. These
   index keywords are not readily visible outside of DRMS (but
   they can be accessed, just like any other keyword).

   To avoid confusion, index keywords are 'internal DRMS prime' and
   slotted keywords are 'external DRMS prime'.

   Functions that access 'internal DRMS prime' keywords provide kPkeysDRMSInternal as a parameter
   to indicate that they want DRMS keywords that contain the index keyword.
   Functions that provide kPkeysDRMSExternal as a parameter
   to indicate that they want DRMS keywords that contain the slotted keyword.
*/
enum DRMS_PrimeKeyType_enum
{
   kPkeysDRMSInternal = 0,
   kPkeysDRMSExternal
};

typedef enum DRMS_PrimeKeyType_enum DRMS_PrimeKeyType_t;

enum DRMS_KeywordFlag_enum
{
   /* If per_segment == 1 then this keyword is one
      of a set of keywords and pertains to a single
      segment in the record. If the keyword name is
      "blah" then keywords in this set are
      "blah[0]", "blah[1]", etc. */
   kKeywordFlag_PerSegment      = 0x00000001,

   /* Certain keywords are not specified in the .jsd, but instead are created
    * as a consequence of the presence of other keywords/segments/links in the
    * .jsd.  These keywords are known as "implicit" keywords as they are implicitly
    * created.  They are part of a record's "keywords" container, but they shouldn't
    * be part of any .jsd
    */
   kKeywordFlag_Implicit        = 0x00000002,
   /* There are 3 kinds of primary indices:
    * 1. The psql primary index
    * 2. The DRMS-internal primary index
    * 3. The DRMS-external primary index
    *
    * The first is what psql uses in the series tables to determine row uniqueness.
    * The second is what DRMS uses in its psql queries to uniquely find a DRMS record.
    * The third is what a module calling into DRMS uses as the primary key.  An
    * example with slotted keys will make this clear.  Suppose there are two keywords
    * in a series, TOBS and TOBS_index, where TOBS is slotted, and TOBS_index is the
    * associated index keyword.  The DRMS-external primary index is (TOBS).  The user
    * simply provides a time string to uniquely find a record.  The DRMS-internal primary
    * index is (TOBS_index).  DRMS will query psql by specifying an index value in
    * the psql query (psql may return more than one record, but DRMS will then take
    * the one with maximum recnum).  The psql primary index is (recnum, TOBS_index).
    *
    * Each series has a pidx_keywords field which identifies the
    * DRMS-internal primary index.
    */
   kKeywordFlag_InternalPrime   = 0x00000004,
   kKeywordFlag_ExternalPrime   = 0x00000008
};

typedef enum DRMS_KeywordFlag_enum DRMS_KeywordFlag_t;


/* Classes of keywords - each class is a certain combination of DRMS_KeywordFlag_t */

/** @brief DRMS Keyword Classes */
enum DRMS_KeywordClass_enum
{
   /** @brief All DRMS keywords are members of this class.*/
   kDRMS_KeyClass_All = 0,
   /** @brief DRMS keywords that have been explicitly defined in a .jsd are members of this class.
       Keywords that are implicitly created (eg, index keywords) are not. */
   kDRMS_KeyClass_Explicit,
   /** @brief DRMS keywords that compose the DRMS primary index are members of this class. */
   kDRMS_KeyClass_DRMSPrime,
   /** @brief DRMS keywords whose persegment flag is set are members of this class. */
   kDRMS_KeyClass_Persegment
};

typedef enum DRMS_KeywordClass_enum DRMS_KeywordClass_t;

typedef struct  DRMS_KeywordInfo_struct
{
  char name[DRMS_MAXKEYNAMELEN];         /* Keyword name. */

  /************ Link keywords ***********/
  /* If this is an inherited keyword, islink is non-zero,
     and linkname holds the name of the link which points
     to the record holding the actual keyword value. */
  int  islink;
  char linkname[DRMS_MAXLINKNAMELEN];   /* Link to inherit from. */
  char target_key[DRMS_MAXKEYNAMELEN]; /* Keyword to inherit.  */

  /************ Regular keywords ********/
  DRMS_Type_t type;               /* Keyword type. */
  char format[DRMS_MAXFORMATLEN]; /* Format string for formatted input
                                     and output. */
  char unit[DRMS_MAXUNITLEN];     /* Physical unit. */
  char description[DRMS_MAXCOMMENTLEN];
  DRMS_RecScopeType_t recscope;   /* If recscope == 0, then this keyword
				   * has values that vary across records.
				   * If recscope == 1, then this keyword
				   * is constant across all records.
				   * If recscope is not 0 or 1, then
				   * the keyword is 'slotted'.  This means
				   * that the value of the keyword is
				   * placed into a slot (eg, rounded down)
				   * before being placed into the database.
                                   * rescope is stored in the "isconstant"
                                   * field of the drms_keyword table in the
                                   * database. */

  int kwflags;                    /* See DRMS_KeywordFlag_enum for the definitions
                                   * of these flags.  These flags are stored as bits
                                   * of a 16-bit integer, and saved in PG in
                                   * the lower 16 bits of the "persegment" column of the "drms_keyword"
                                   * table. The upper 16 bits contains the rank of the keyword.
                                   */
  int rank;                       /* The order in which this keyword was created
                                   * during drms_insert_series(). 0 means it was
                                   * the first keyword in its series. This is stored in PG as
                                   * a 16-bit integer in the upper 16 bits of the "persegment"
                                   * column of the "drms_keyword" table. */

} DRMS_KeywordInfo_t;

/**
DRMS keyword struct
*/
struct DRMS_Keyword_struct
{
  struct DRMS_Record_struct *record; /* The record this keyword belongs to.*/
  struct  DRMS_KeywordInfo_struct *info; /* Series-wide info. */
  DRMS_Type_Value_t value;               /* Keyword data. If this keyword is in
					  * the series cache, it contains the
					  * default value. */
};

/** \brief DRMS keyword struct reference */
typedef struct DRMS_Keyword_struct DRMS_Keyword_t;

/**************************** Links ***************************/

/* Links to other objects from which keyword values can be inherited.
   A link often indicates that the present object was computed using the
   data in the object pointed to. */

typedef enum { STATIC_LINK, DYNAMIC_LINK } DRMS_Link_Type_t;

/* Series-wide Link info that does not vary from record to record. */
typedef struct DRMS_LinkInfo_struct
{
  char name[DRMS_MAXLINKNAMELEN];          /* Link name. */
  char target_series[DRMS_MAXSERIESNAMELEN]; /* Series pointed to. */
  char description[DRMS_MAXCOMMENTLEN];
  DRMS_Link_Type_t type;               /* Static or dynamic. */

  /*** Dynamic link info ***/
  int pidx_num;  /* Number of keywords in primary index of target series. */
  DRMS_Type_t pidx_type[DRMS_MAXPRIMIDX]; /* Type of primary index values. */
  char *pidx_name[DRMS_MAXPRIMIDX];
  int rank;                       /* The order in which this link was created
                                   * during drms_insert_series(). 0 means it was
                                   * the first link in its series. */
} DRMS_LinkInfo_t;

/** \brief DRMS link struct */
struct DRMS_Link_struct
{
  struct DRMS_Record_struct *record;   /* The record this link belongs to. */
  DRMS_LinkInfo_t *info;

  /*** Static link info ***/
  long long recnum;          /* recnum = -1 marks a unset link */
                             /* For static link, it is the recnum of the target */
                             /* ART - for dynamic link, this holds the target recnum too (if drms_link_resolve()
                              * was called).  */

  /*** Dynamic link info ***/
  int isset;
  DRMS_Type_Value_t pidx_value[DRMS_MAXPRIMIDX]; /* Primary index values of
						    target record(s). */

  int wasFollowed; /* If a linked-record struct was allocated as a result of a visit to the database
                    * (e.g., because drms_link_follow() was called), then this is set to 1. If this
                    * is the case, then when the original record (source) is freed, then linked record
                    * (target) is freed too. But if a user happens to open the original record
                    * and the linked record independently, then wasFollowed == 0, and if the user
                    * frees the original record, the linked record should not be freed.
                    *
                    * A linked record can be followed only once.
                    */
};

/** \brief DRMS link struct reference */
typedef struct DRMS_Link_struct DRMS_Link_t;

/********************************** Data Segments ***************************/

/* An n-dimensional array (e.g. part or all of a segment array)
   stored consecutively in memory. */
/**
    \brief DRMS array struct

    The ::DRMS_Array_t data stucture represents an n-dimensional array of scalar
    data.  It is used for internal memory access to data structures read
    from, or to be written to, record segments. The array data are stored in
    column-major order at the memory location pointed to by the @ref data
    element.

    The fields @ref israw, @ref bscale, and @ref bzero describe
    how the data contained in the array data structure relate to
    the "true" values they are supposed to represent.
    In the most frequently used case, @ref israw=0,
    the data stored in memory represent the "true" values of the array,
    and @ref bzero and @ref bscale contain
    the shift and scaling (if any) applied to the data when they were
    read in from external storage. If @ref israw=1, then
    the data stored in memory represent the unscaled "raw" values of
    the array, and the true values may be obtained by applying the
    scaling transformations, if any:

    \code
    f(x) = bzero + bscale * x, if x != MISSING
         = MISSING           , if x == MISSING
    \endcode

    If the array struct contains data from a DRMS data segment, as returned
    by the functions
    ::drms_segment_readslice or ::drms_segment_read, then the
    @ref parent_segment  field points to the data segment from which the
    array data originate.

    If the array contains a slice of the parent then the  @ref start field
    contains the starting indices of the slice in the parent array.
    For example: If an array contains the lower 2x2 elements of a 4x3 data
    segment then the struct would contain

    \code
    array.naxis = 2
    array.axis = [2,2]
    array.start = [2,1]
    \endcode
*/
struct DRMS_Array_struct
{
  /* Array info: */
  /** \brief Datatype of the data elements. */
  DRMS_Type_t type;
  /** \brief Number of dimensions. */
  int naxis;
  /** \brief Size of each dimension. */
  int axis[DRMS_MAXRANK];
  /** \brief Data stored in column major order. */
  void *data;

  /* Fields relating to scaling and slicing. */
  /** \brief Parent segment. */
  struct DRMS_Segment_struct *parent_segment;
  /** \brief Zero point for parent->child mapping. */
  double bzero;
  /**
     \brief Do the values represent true values?
     Is this read in with type=DRMS_TYPE_RAW?
     If israw==0 then shift and scaling have been
     applied to the data and they represent the
     "true" values. If israw==1 then no shift
     and scaling have been applied to the data.
  */
  int israw;
  /** \brief Slope for parent->child. */
  double bscale;
  /** \brief Start offset of slice in parent. */
  int start[DRMS_MAXRANK];

  /* Private fields used for array index calculation etc. */
  /** \brief Dimension offset multipliers. */
  int dope[DRMS_MAXRANK];

  /* Private fields used for packed string arrays. */
  /** \brief String buffer used for packed string arrays. */
  char *strbuf;
  /** \brief Size of string buffer. */
  long long buflen;
};

/** \brief DRMS array struct reference*/
typedef struct DRMS_Array_struct DRMS_Array_t;



/*
     For an array-slice the parent_xxx variables describe how the array
     maps into the parent array. parent_naxis is the number of dimensions
     in the parent array. naxis is the number of dimensions of the slice,
     i.e. parent_naxis minus the number of singleton dimensions where
     parent_start[i] = parent_end[i]. The cutout is stored in "squeezed"
     form with the singleton dimensions removed.
     Example: If the (integer) parent array is

          [ 1 4 7 ]
          [ 2 5 8 ]
          [ 3 6 9 ]

     with the Array_t struct

	  type = DRMS_TYPE_INT
          naxis = 2,
          axis = {3,3}
          (int *) data = {1,2,3,4,5,6,7,8,9}

     and we wanted to represent the last two elements [ 6 9 ] of the
     bottom row as a slice. The resulting Array_Slice_t structure would have


	  array.type = DRMS_TYPE_INT
          array.naxis = 1,
          array.axis = {2} ,
          array.data = {6, 9}
          parent_naxis = 2
          parent_axis = {3,3}
	  parent_type = DRMS_TYPE_INT
	  parent_start = {2, 1}
          parent_end = {2, 2}
          bscale = 1.0
          bzero  = 0.0

     data points to an array holding the data of the cutout stored
     in column major order.

     In general, the mapping from parent to child can be described as

      child(0:axis[i]-1,...,0:axis[naxis-1]) =
          squeeze(bzero+bscale*parent(s0:e0,s1:e1,...,sn:en)) ,

     where si = parent_start[i], ei = parent_end[i],
     n+1 = parent_naxis >= naxis, and squeeze(*) is the operator
     that compacts the array by removing singleton dimensions
     where si=ei.
  */


/* The data descriptors hold basic information about the in-memory
   representation of the data. */
/**
   \brief DRMS segment scope types
*/
typedef enum  {
   /** \brief Indicates data is constant across records */
   DRMS_CONSTANT,
   /** \brief Indicates data dimension structure is constant across records */
   DRMS_VARIABLE,
   /** \brief Indicates data dimension structure varies across records */
   DRMS_VARDIM
} DRMS_Segment_Scope_t;

#ifndef DRMS_TYPES_C
extern char *drms_segmentscope_names[];
#else
char *drms_segmentscope_names[] = {"constant", "variable", "vardim"};

#endif


/***********************************************************
 *
 * Segments
 *
 ***********************************************************/

/* A data segment is typically an n-dimensional array of a simple type.
   It can also be a "generic" segment which is just a file
   (structure-less as far as DRMS is concerned). */

/** \brief DRMS segment dimension info struct */
struct DRMS_SegmentDimInfo_struct {
  /** \brief Number of dimensions (rank) */
  int naxis;
  /** \brief Length of each dimension */
  int axis[DRMS_MAXRANK];
};

/** \brief DRMS segment dim info struct reference */
typedef struct DRMS_SegmentDimInfo_struct DRMS_SegmentDimInfo_t;

/** \brief DRMS segment info struct */
struct DRMS_SegmentInfo_struct {
						   /*  Context information:  */
  /** \brief Segment name */
  char name[DRMS_MAXSEGNAMELEN];
  /** \brief Segment number in record */
  int segnum;                     /* The order in which this segment was created
                                   * during drms_insert_series(). 0 means it was
                                   * the first segment in its series. */
  /** \brief  Description string */
  char description[DRMS_MAXCOMMENTLEN];
		/************  Link segments  ***********/
		/*  If this is an inherited segment, islink is non-zero,
	and linkname holds the name of the link which points to the record
						 holding the actual segment. */
  /** \brief Non-0 if segment inherited */
  int  islink;
  /** \brief Link to inherit from */
  char linkname[DRMS_MAXLINKNAMELEN];
  /** \brief Segment to inherit */
  char target_seg[DRMS_MAXSEGNAMELEN];
  /** \brief Datatype of data elements */
  DRMS_Type_t type;
  /** \brief Number of dimensions (rank) */
  int naxis;
  /** \brief Physical unit */
  char unit[DRMS_MAXUNITLEN];
  /** \brief Storage protocol */
  DRMS_Protocol_t protocol;
  /** \brief Const, Varies, or DimsVary */
  DRMS_Segment_Scope_t scope;
  /** \brief Record number where constant segment is stored */
  long long cseg_recnum;
};

/** \brief DRMS segment info struct reference */
typedef struct DRMS_SegmentInfo_struct DRMS_SegmentInfo_t;

/**
    \brief DRMS segment struct

    A DRMS data segment corresponds to a named file, typically containing an
    n-dimensional scalar array. (It can also be a "generic" segment, which is
    just an unstructured file as far as DRMS is concerned.) One or more segments
    constitute the external data part(s) of the DRMS record pointed to by the
    @ref record field. The
    @ref info field points to a structure containing attributes common to all
    records in a series, while the segment structure itself contains the fields
    @ref axis and @ref blocksize that can vary from record to record if
    @ref scope=::DRMS_VARDIM.

    The @ref protocol field determines the external storage format used for
    storing segment data. Only protocols ::DRMS_BINARY, ::DRMS_BINZIP, ::DRMS_FITS,
    ::DRMS_FITZ, ::DRMS_GENERIC, and ::DRMS_TAS are fully supported in the base
    DRMS system (NetDRMS). Protocol ::DRMS_DSDS is a
    special protocol for dealing with the format of the Stanford SOI-MDI
    Data Sorage and Distribution System (DSDS) and requires support outside
    the DRMS library. Protocol ::DRMS_LOCAL likewise supports the DSDS file-format
    and requires a non-NetDRMS library. It differs from ::DRMS_DSDS in that
    it does not depend on the presence of DSDS - it merely allows the user
    to operate on files external to DSDS (eg., files that may reside on a LOCAL
    hard disk) that happen to have the file format that DSDS uses.
    ::DRMS_GENERIC and ::DRMS_MSI are also reserved for unsupported
    data formats. In particular, the DRMS_GENERIC protocol is used to refer
    to any unstructured data format or data formats of unknown structure.

    Data storage for ::DRMS_FITS is in minimal simple FITS files, without
    extensions and with only the compliance- and structure-defining keywords
    (SIMPLE, BITPIX, NAXIS, NAXISn, and END, and optionally BLANK, BSCALE and
    BZERO) in the headers. All other ancillary data are to be found in the DRMS
    record. For the ::DRMS_FITZ protocol, the representation is similar except
    that the entire FITS file is compressed with Rice compression. (Note that
    because the memory representation for the data supported through the
    API functions ::drms_segment_read is the ::DRMS_Array_t struct, which has a
    maximum rank of 16, FITS hypercubes of dimension > 16 are not supported.)

    For the
    ::DRMS_BINARY protocol, the data are written in a binary format, in which
    the first 8 bytes are the characters "DRMS RAW", the next @c 8(@c n+1)
    are little-endian integer representations of the data type, rank, and
    dimensions of the @a n axes, and the remainder the binary data in
    little-endian format. For the ::DRMS_BINZIP protocol the represntation is
    the same, except that the file is gzip compressed. The ::DRMS_TAS protocol
    (for "Tiled Array Storage") is described elsewhere, if at all. It is
    designed for use with data segments that are small compared with the
    size of the full data records, in order to minimize file access without
    keeping all of the segment data in the relational database, by concatenating
    multiple segments in the external format. The segment @ref blocksize member
    is for use with the ::DRMS_TAS protocol.

    Segment data types refer to the scalar data type for the segment, and
    should be mostly self-explanatory. ::DRMS_TYPE_TIME is a special case of
    double-precision floating point values representing elapsed time from
    a fixed epoch. Arithmetic is the same as for ::DRMS_TYPE_DOUBLE, only the
    format for string representations differs from that for normal floating-point
    data; see ::sprint_time. Data of type ::DRMS_TYPE_STRING are
    null-terminated byte sequences of any length.  Data type ::DRMS_TYPE_STRING is
    not supported by the protocols ::DRMS_BINARY, ::DRMS_BINZIP, ::DRMS_FITS, nor
    ::DRMS_FITZ. Whether it is properly supported by the ::DRMS_TAS protocol is
    doubtful. The data type ::DRMS_TYPE_RAW is used to describe data that are not
    to be converted on read from the type of their external representation,
    which must then be established for type-specific operations. It should
    be used for ::DRMS_Array_t structures only, not for DRMS segments.

    The scope of a segment can take on three values. The normal scope is
    expected to be ::DRMS_VARIABLE, for which the particular segment for every
    record has exactly the same structure (rank and dimensions),
    only the actual data values vary from one record to another. (Note that
    different segments of a record, however, need not have the same structure
    as one another.) If the scope is ::DRMS_VARDIM, then the dimensions and
    even rank of the particular segment may vary from one record to another,
    although other features of the segment, in particular the data type,
    must still be the same. Scope ::DRMS_CONSTANT is used to describe a data
    segment that is constant for all records. It can be used for example to
    describe a location index array, or a constant calibration array that
    applies to all records in the series, so that it can be made available
    to any record without having to store multiple instances externally.

*/
struct DRMS_Segment_struct {
  /** \brief  The record this segment belongs to */
  struct DRMS_Record_struct *record;
  /** \brief Contains attributes common to all records in a series */
  DRMS_SegmentInfo_t *info;
  /* For TAS, filename will be constant across records. */
  /** \brief Storage file name  */
  char filename[DRMS_MAXSEGFILENAME];
  /** \brief Size of each dimension */
  int axis[DRMS_MAXRANK];
  /** \brief Block sizes for TAS storage */
  int blocksize[DRMS_MAXRANK];
  char cparms[DRMS_MAXCPARMS];
  /* For TAS, the values of bzero and bscale of each record MUST match the FITS header's values. */
  /** \brief Data scaling offset */
  double bzero;
  /** \brief Data scaling factor */
  double bscale;
};

/** \brief DRMS segment struct reference */
typedef struct DRMS_Segment_struct DRMS_Segment_t;

#define DRMS_READONLY  1
#define DRMS_READWRITE 2
typedef struct DRMS_StorageUnit_struct {
  struct DRMS_SeriesInfo_struct *seriesinfo; /* global series info. */
  int mode;  /* Indicates if SU is open for DRMS_READONLY or DRMS_READWRITE */
  long long sunum; /* Unique index of this storage unit. */
  char sudir[DRMS_MAXPATHLEN];  /* Directory of this storage unit. */
  int refcount; /* Number of Records pointing to this storage unit struct. */
  int nfree;     /* Number of free record slots in this storage unit.
		    Total number of slots is in seriesinfo.unitsize. */
  char *state; /* Bytemap of slot states. Valid states are DRMS_SLOT_FREE,
                  DRMS_SLOT_FULL, and DRMS_SLOT_TEMP. The latter means that
		  the record should be committed to SUMS as temporary
		  regardless of the archive method in the series definition.
		  A storage unit will be archived as temporary of it is
		  defined thus in the series definition or if all non-empty
		  slots have state DRMS_SLOT_TEMP. */
  long long *recnum; /* Record numbers of records occupying the slots of this
		   storage unit. Only used on the server side to delete
		   temporary records at the end of a session. */
} DRMS_StorageUnit_t;


typedef struct DRMS_SuAndSeries_struct
{
  long long sunum;
  char *series;
} DRMS_SuAndSeries_t;


/* When the record-set parser runs, it fills in a bit mask that describes the various elements of
 * the record-set query just parsed.
 *
 * bits:
 * 0x00000001 - has >= 1 filter
 * 0x00000002 - has @file
 * 0x00000004
 * 0x00000008
 * 0x00000010
 */
typedef int DRMS_RecQueryInfo_t;

enum DRMS_RecQueryInfoFlag_enum
{
   kFilters = 0x00000001, // has >= 1 filter
   kAtFile  = 0x00000002  // has @file
};

typedef enum DRMS_RecQueryInfoFlag_enum DRMS_RecQueryInfoFlag_t;

/*********** Various utility functions ****************/
DRMS_Type_t drms_str2type(const char *);

/**
   \brief Return a string representation of a ::DRMS_Type_t value.

   \param type The ::DRMS_Type_t whose string representation is to
   be returned.
   \return String representation of the specified ::DRMS_Type_t value.
*/
const char *drms_type2str(DRMS_Type_t type);
void drms_missing(DRMS_Type_t type, DRMS_Type_Value_t *val);
void drms_missing_vp(DRMS_Type_t type, void *val);
int drms_copy_db2drms(DRMS_Type_t drms_type, DRMS_Type_Value_t *drms_dst,
		      DB_Type_t db_type, char *db_src);
void drms_copy_drms2drms(DRMS_Type_t type, DRMS_Type_Value_t *dst,
			 DRMS_Type_Value_t *src);
DB_Type_t drms2dbtype(DRMS_Type_t type);
int drms_sizeof(DRMS_Type_t type);
void *drms_addr(DRMS_Type_t type, DRMS_Type_Value_t *val);
int drms_strval(DRMS_Type_t type, DRMS_Type_Value_t *val, char *str);
int drms_sprintfval(char *dst, DRMS_Type_t type, DRMS_Type_Value_t *val, int internal);
int drms_sprintfval_format(char *dst, DRMS_Type_t type, DRMS_Type_Value_t *val,
			   char *format, int internal);
int drms_printfval (DRMS_Type_t type, DRMS_Type_Value_t *val);
int drms_fprintfval(FILE *keyfile, DRMS_Type_t type, DRMS_Type_Value_t *val);
int drms_sscanf_str(const char *str, const char *delim, DRMS_Type_Value_t *dst);
int drms_sscanf_str3(const char *str, const char *delim, int binary, DRMS_Type_Value_t *dst);
int drms_sscanf2(const char *str, const char *delim, int silent, DRMS_Type_t dsttype, DRMS_Value_t *dst);
int drms_sscanf3(const char *str, const char *delim, int silent, DRMS_Type_t dsttype, int binary, DRMS_Value_t *dst);

/* Scalar conversion functions. */
int drms_convert(DRMS_Type_t dsttype, DRMS_Type_Value_t *dst,
		 DRMS_Type_t srctype, DRMS_Type_Value_t *src);
int drms_convert_array(DRMS_Type_t dsttype, char *dst,
		       DRMS_Type_t srctype, char *src);
char drms2char(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
short drms2short(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
int drms2int(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
long long drms2longlong(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
long long conv2longlong(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
float drms2float(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
double drms2double(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
double drms2time(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);
char *drms2string(DRMS_Type_t type, DRMS_Type_Value_t *value, int *status);

/* Misc. utility functions. */
int drms_printfval_raw(DRMS_Type_t type, void *val);
int drms_fprintfval_raw(FILE *keyfile, DRMS_Type_t type, void *val);
long long drms_types_strtoll(const char *str, DRMS_Type_t inttype, int *consumed, int *status);
void drms_byteswap(DRMS_Type_t type, int n, char *val);
void drms_memset(DRMS_Type_t type, int n, void *array, DRMS_Type_Value_t val);
int drms_daxpy(DRMS_Type_t type, const double alpha, DRMS_Type_Value_t *x,
	       DRMS_Type_Value_t *y );
int drms_equal(DRMS_Type_t type, DRMS_Type_Value_t *x, DRMS_Type_Value_t *y);

/* time stuff */
const TIME *drms_time_getepoch(const char *str, DRMS_TimeEpoch_t *epochenum, int *status);
void drms_time_term();

/* sdo_s is number of whole seconds since the SDO EPOCH
 * sdo_ss is number of subseconds since SDO_EPOCH + sdo_s
 *   where a subsecond is 1/(2^16) of a second */
static inline TIME _SDO_to_DRMS_time(int sdo_s, int sdo_ss)
{
   return(SDO_EPOCH + (TIME)sdo_s + (TIME)sdo_ss/65536.0);
}

/* Frees value, only if it is of type string. */
static inline void drms_value_free(DRMS_Value_t *val)
{
   if (val && val->type == DRMS_TYPE_STRING && val->value.string_val)
   {
      free(val->value.string_val);
      val->value.string_val = NULL;
   }
}

/* T  - Data type (DRMS_Type_t)
 * IV - Input data value (void *)
 * OV - Output value (DRMS_Value_t)
 */
#define DRMS_VAL_SET(T, IV, OV)                                 \
{                                                               \
   int vserror = 0;                                             \
   switch (T)                                                   \
   {                                                            \
      case DRMS_TYPE_CHAR:                                      \
	OV.value.char_val = *(char *)IV;                     \
	break;                                                  \
      case DRMS_TYPE_SHORT:                                     \
	OV.value.short_val = *(short *)IV;                   \
	break;                                                  \
      case DRMS_TYPE_INT:                                       \
	OV.value.int_val = *(int *)IV;                       \
	break;                                                  \
      case DRMS_TYPE_LONGLONG:                                  \
	OV.value.longlong_val = *(long long *)IV;            \
	break;                                                  \
      case DRMS_TYPE_FLOAT:                                     \
	OV.value.float_val = *(float *)IV;                   \
	break;                                                  \
      case DRMS_TYPE_DOUBLE:                                    \
	OV.value.double_val = *(double *)IV;                 \
	break;                                                  \
      case DRMS_TYPE_TIME:                                      \
	OV.value.time_val = *(double *)IV;                   \
	break;                                                  \
      case DRMS_TYPE_STRING:                                    \
	OV.value.string_val = strdup((char *)IV);            \
	break;                                                  \
      default:                                                  \
	fprintf(stderr, "Invalid drms type: %d\n", (int)T);     \
	vserror = 1;                                            \
   }                                                            \
   if (!vserror)                                                \
   {                                                            \
      OV.type = T;                                              \
   }                                                            \
}

/* Arithmetic operations */
/* XXX - need to flesh these out, or else this DRMS_Type_Value concept doesn't
 * seem to be that useful.
 */

/* need to check for overflow */


/* This appears to get inlined */
static inline DRMS_Value_t drms_val_add(DRMS_Value_t *a, DRMS_Value_t *b)
{
   DRMS_Value_t ans;

   if (a->type == b->type)
   {
      ans.type = a->type;

      switch(a->type)
      {
	 case DRMS_TYPE_CHAR:
	   {
	      int sum = (a->value).char_val + (b->value).char_val;

	      if (sum >= SCHAR_MIN && sum <= SCHAR_MAX)
	      {
		 ans.value.char_val = (char)sum;
	      }
	   }
	   break;
	 case DRMS_TYPE_SHORT:
	   {
	      int sum = (a->value).short_val + (b->value).short_val;

	      if (sum >= SHRT_MIN && sum <= SHRT_MAX)
	      {
		 ans.value.short_val = (short)sum;
	      }
	   }
	   break;
	 case DRMS_TYPE_INT:
	   {
	      long long sum = (a->value).int_val + (b->value).int_val;

	      if (sum >= INT_MIN && sum <= INT_MAX)
	      {
		 ans.value.int_val = (int)sum;
	      }
	   }
	   break;
	 case DRMS_TYPE_LONGLONG:
	   {
	      long long sum = (a->value).longlong_val + (b->value).longlong_val;
	      ans.value.longlong_val = sum;
	   }
	   break;
	 case DRMS_TYPE_FLOAT:
	   {
	      double sum = (a->value).float_val + (b->value).float_val;

	      if (sum >= -FLT_MAX && sum <= FLT_MAX)
	      {
		 ans.value.float_val = (float)sum;
	      }
	   }
	   break;
	 case DRMS_TYPE_DOUBLE:
	   {
	      double sum = (a->value).double_val + (b->value).double_val;
	      ans.value.double_val = sum;
	   }
	   break;
	 default:
	   fprintf(stderr, "drms_val_add(): unsupported type.\n");
      }
   }
   else
   {
      fprintf(stderr, "drms_val_add(): type mismatch.\n");
   }

   return ans;
}

static inline DRMS_Value_t drms_val_div(DRMS_Value_t *a, DRMS_Value_t *b)
{
   DRMS_Value_t ans;

   if (a->type == b->type)
   {
      ans.type = a->type;

      switch(a->type)
      {
	 case DRMS_TYPE_CHAR:
	   {
	      int res = (int)((a->value).char_val) / (int)((b->value).char_val);

	      if (res >= SCHAR_MIN && res <= SCHAR_MAX)
	      {
		 ans.value.char_val = (char)res;
	      }
	   }
	   break;
	 case DRMS_TYPE_SHORT:
	   {
	      int res = (int)((a->value).short_val) / (int)((b->value).short_val);

	      if (res >= SHRT_MIN && res <= SHRT_MAX)
	      {
		 ans.value.short_val = (short)res;
	      }
	   }
	   break;
	 case DRMS_TYPE_INT:
	   {
	      long long res = (a->value).int_val / (b->value).int_val;

	      if (res >= INT_MIN && res <= INT_MAX)
	      {
		 ans.value.int_val = (int)res;
	      }
	   }
	   break;
	 case DRMS_TYPE_LONGLONG:
	   {
	      long long res = (a->value).longlong_val / (b->value).longlong_val;
	      ans.value.longlong_val = res;
	   }
	   break;
	 case DRMS_TYPE_FLOAT:
	   {
	      double res = (double)((a->value).float_val) / (double)((b->value).float_val);

	      if (res >= -FLT_MAX && res <= FLT_MAX)
	      {
		 ans.value.float_val = (float)res;
	      }
	   }
	   break;
	 case DRMS_TYPE_DOUBLE:
	   {
	      double res = (a->value).double_val / (b->value).double_val;
	      ans.value.double_val = res;
	   }
	   break;
	 default:
	   fprintf(stderr, "drms_val_div(): unsupported type.\n");
      }
   }
   else
   {
      fprintf(stderr, "drms_val_add(): type mismatch.\n");
   }

   return ans;
}

/* Doxygen comments */

/* lame doxygen - don't put @brief in here; it doesn't work (some kind of doxygen bug) */

/** @typedef typedef enum DRMS_KeywordClass_enum DRMS_KeywordClass_t
    DRMS Keyword Classes Reference (see ::DRMS_KeywordClass_enum)
*/

#endif
