#ifndef __SUM_RPC_H
#define __SUM_RPC_H

/*
 * This file was originally generated by rpcgen and then edited.
 * (copied from /home/jim/STAGING/src/pipe/rpc/pe_rpc.h)
 */
#include <SUM.h>
#include <rpc/rpc.h>
#include <soi_key.h>
#if defined(SUMS_TAPE_AVAILABLE) && SUMS_TAPE_AVAILABLE
  #include <tape.h>
#endif
#include <sum_info.h>

/* !!TBD fix up these defs */
//#define OFFSITEHOST "d00.stanford.edu" //offsite hostname to send .md5 files
#define OFFSITEDIR "/dds/socdc" /* offsite dir to put .md5 files */
#define MAX_PART 1024		/* max # +1 of dedicated /SUM partitions */
#define MAXSUMSETS 4		/* max # of SUM sets */
#define MAXSUMOPEN 16		/* max# of SUM opens for a single client */
#define MAXSUMREQCNT 512	/* max# of SU that can request in a single
			         * SUM_get() call */
#define MAX_STR 256		/* max size of a char[] */
#define MAXSTRING 4096
#define SUMARRAYSZ MAXSUMREQCNT	/* num of entries in SUM_t * arrays malloced */
#define MAXSUNUMARRAY 65536     /* max sunums in struct Sunumarray */
#define RESPWAIT 30             /* secs to wait for completion response */
#define RPCMSG 2
#define TIMEOUTMSG 3
#define ERRMESS 4
#define ERRMSG 4
/* Define the storage sets used in sum->storeset */
#define JSOC 0		/* NOTE: JSOC must be 0 */
#define LKHD 1		/* Lockheed pds_set_num for the AIA disks */

/* Note: Do NOT change the following. They are in the database */
#define DARW 1          /* data allocate assigned as read/write */
#define DADP 2          /* data allocate deletion pending when effective date
*/
#define DAAP 4          /* data allocate archive pending */
#define DARO 8          /* data request assigned as read only */
#define DAPERM 16       /* data allocate is permanent */
#define DASAP 32        /* data allocate safe archive pending */
/* Here are sub-statuses for DAAP */
#define DAAEDDP 32      /* don't archive and when effective date mark DADP */
#define DAAPERM 64      /* archive then mark DAPERM */
#define DAADP 128       /* archive then mark DADP when effective date */
/* Here are sub-statuses for DADP */
#define DADMVA 256      /* active ds move, don't delete wd */
#define DADMVC 512      /* ds has been moved, don't mark offline when rm wd */
#define DADPDELSU 1024  /* delete_series has called SUM_delete_series() */
		        /* don't rm the records in Records.txt in the dir */


/* Handle RPC for 32 or 64 bit machines */
#ifdef _LP64
/*  extern CLIENT *
/*  clnt_create(char *host, uint32_t prog, uint32_t vers, char *proto);
/*
/*  extern enum clnt_stat
/*  clnt_call(CLIENT *clnt, uint32_t procnum, xdrproc_t inproc, char *in, 
/*		xdrproc_t outproc, char *out, struct timeval tout);
/*
/*  extern CLIENT *
/*  clnttcp_create(struct sockaddr_in *addr, unit32_t prognum,unit32_t versnum, 
/*		int *sockp, u_int sendsz, u_int recvsz);
/*
/*  extern bool_t 
/*  pmap_unset(uint32_t prognum, uint32_t versnum);
/*
/*  extern bool_t
/*  svc_register(SVCXPRT *xprt, unit32_t prognum, unit32_t versnum, 
/*		void (*dispatch) (), uint32_t protocol);
/*
/*  void
/*  svc_unregister(unit32_t prognum, unit32_t versnum);
/*
*/
#endif

#ifdef __APPLE__
#define xdr_uint_t xdr_u_int_t    
#define xdr_uint16_t xdr_u_int16_t
#define xdr_uint32_t xdr_u_int32_t
#define xdr_uint64_t xdr_u_int64_t
#endif /* __APPLE__ */

typedef char *nametype;
bool_t xdr_nametype(XDR *xdr, nametype *objp);

struct keyseg {
        nametype name;
        int key_type;
        union {
                nametype val_str;
                char *val_byte;
                u_char *val_ubyte;
                short *val_short;
                u_short *val_ushort;
                int *val_int;
                u_int *val_uint;
                long *val_long;
                u_long *val_ulong;
                uint32_t *val_uint32;
                uint64_t *val_uint64;
                float *val_float;
                double *val_double;
                FILE *val_FILE;
                TIME *val_time;
        } keyseg_u;
};
typedef struct keyseg keyseg;
bool_t xdr_keyseg(XDR *xdrs, keyseg *objp);

/* Note: this must be the same as KEY defined in soi_key.h */
struct Rkey {
        struct Rkey *next;
	keyseg key_segment;
};
typedef struct Rkey Rkey;
bool_t xdr_Rkey(XDR *xdrs, Rkey *objp);

//This is used by the SUMS API SUM_infoArray() to send info to sums
struct Sunumarray {
  int reqcnt;
  int mode;
  int tdays;
  int reqcode;
  uint64_t uid;
  char *username;
  char *machinetype;
  uint64_t *sunums;
};
typedef struct Sunumarray Sunumarray;
bool_t xdr_Sunumarray(XDR *xdrs, Sunumarray *objp);

//This is used by the SUMS API SUM_infoArray() to receive info from sums
struct Sinfoarray {
  int reqcnt;
  int reqcode;
  uint64_t uid;
  SUM_info_t *sinfo;	//defined in sum_info.h
};
typedef struct Sinfoarray Sinfoarray;
bool_t xdr_Sinfoarray(XDR *xdrs, Sinfoarray *objp);
bool_t xdr_sum_info_t(XDR *xdrs, SUM_info_t *objp);


/* This is the sum_svc program registration. Client API sends here */
//First define the prog numbers of the seperate sum functions
#define SUMALLOC ((uint32_t)0x200005e7) /* 536872423 */
#define SUMALLOCV ((uint32_t)1)
#define SUMGET ((uint32_t)0x200005e8) /* 536872424 */
#define SUMGETV ((uint32_t)1)
#define SUMPUT ((uint32_t)0x200005e9) /* 536872425 */
#define SUMPUTV ((uint32_t)1)
#define SUMINFO ((uint32_t)0x200005ea) /* 536872426 */
#define SUMINFOV ((uint32_t)1)
#define SUMDELSER ((uint32_t)0x200005eb) /* 536872427 */
#define SUMDELSERV ((uint32_t)1)
#define SUMINFO1 ((uint32_t)0x200005ec) /* 536872428 */
#define SUMINFO2 ((uint32_t)0x200005ed) /* 536872429 */
#define SUMPUT1 ((uint32_t)0x200005ee) /* 536872430 */
#define SUMPUT2 ((uint32_t)0x200005ef) /* 536872431 */
#define SUMGET1 ((uint32_t)0x200005f0) /* 536872432 */
#define SUMGET2 ((uint32_t)0x200005f1) /* 536872433 */
#define SUMALLOC1 ((uint32_t)0x200005f2) /* 536872434 */
#define SUMALLOC2 ((uint32_t)0x200005f3) /* 536872435 */
#define SUMOPEN ((uint32_t)0x200005f4) /* 536872436 */
#define SUMOPENV ((uint32_t)1)
#define SUMOPEN1 ((uint32_t)0x200005f5) /* 536872437 */
#define SUMOPEN2 ((uint32_t)0x200005f6) /* 536872438 */
#define SUMOPEN3 ((uint32_t)0x200005f7) /* 536872439 */
#define SUMOPEN4 ((uint32_t)0x200005f8) /* 536872440 */
#define SUMOPEN5 ((uint32_t)0x200005f9) /* 536872441 */
#define SUMOPEN6 ((uint32_t)0x200005fa) /* 536872442 */
#define SUMOPEN7 ((uint32_t)0x200005fb) /* 536872443 */
#define SUMALLOC3 ((uint32_t)0x200005fc) /* 536872444 */
#define SUMALLOC4 ((uint32_t)0x200005fd) /* 536872445 */
#define SUMALLOC5 ((uint32_t)0x200005fe) /* 536872446 */
#define SUMALLOC6 ((uint32_t)0x200005ff) /* 536872447 */
#define SUMALLOC7 ((uint32_t)0x20000600) /* 536872448 */
#define SUMGET3 ((uint32_t)0x20000601) /* 536872449 */
#define SUMGET4 ((uint32_t)0x20000602) /* 536872450 */
#define SUMGET5 ((uint32_t)0x20000603) /* 536872451 */
#define SUMGET6 ((uint32_t)0x20000604) /* 536872452 */
#define SUMGET7 ((uint32_t)0x20000605) /* 536872453 */
#define SUMPUT3 ((uint32_t)0x20000606) /* 536872454 */
#define SUMPUT4 ((uint32_t)0x20000607) /* 536872455 */
#define SUMPUT5 ((uint32_t)0x20000608) /* 536872456 */
#define SUMPUT6 ((uint32_t)0x20000609) /* 536872457 */
#define SUMPUT7 ((uint32_t)0x2000060a) /* 536872458 */
#define SUMINFO3 ((uint32_t)0x2000060b) /* 536872459 */
#define SUMINFO4 ((uint32_t)0x2000060c) /* 536872460 */
#define SUMINFO5 ((uint32_t)0x2000060d) /* 536872461 */
#define SUMINFO6 ((uint32_t)0x2000060e) /* 536872462 */
#define SUMINFO7 ((uint32_t)0x2000060f) /* 536872463 */

#define SUMPROG ((uint32_t)0x20000611) /* 536872465 */
#define SUMVERS ((uint32_t)1)
#define SUMDO ((uint32_t)1)
#define OPENDO ((uint32_t)2)
#define CLOSEDO ((uint32_t)3)
#define GETDO ((uint32_t)4)
#define SUMRESPDO ((uint32_t)5)
#define ALLOCDO ((uint32_t)6)
#define PUTDO ((uint32_t)7)
#define ARCHSUDO ((uint32_t)8)
/**********************************
#define APUPDO ((uint32_t)8)
#define DPUPDO ((uint32_t)9)
#define SUMRMDO ((uint32_t)10)
**********************************/
#define DEBUGDO ((uint32_t)11)
#define DELSERIESDO ((uint32_t)12)
#define INFODO ((uint32_t)13)
#define SHUTDO ((uint32_t)14)
#define INFODOX ((uint32_t)15)
#define NOPDO ((uint32_t)16)
#define TAPERECONNECTDO ((uint32_t)17)
#define CONFIGDO ((uint32_t)18)
#define INFODOARRAY ((uint32_t)19)
#define SUMREPARTN ((uint32_t)20)

extern KEY *sumdo_1(void);
extern KEY *opendo_1(void);
extern KEY *shutdo_1(void);
extern KEY *closedo_1(void);
extern KEY *getdo_1(void);
extern KEY *infodo_1(void);
extern KEY *infodoX_1(void);
extern KEY *infodoX_1_U(void);
extern KEY *infodoArray_1(void);
extern KEY *sumrespdo_1(void);
extern KEY *allocdo_1(void);
extern KEY *putdo_1(void);
extern KEY *archsudo_1(void);
extern KEY *nopdo_1(void);
extern KEY *tapereconnectdo_1(void);
/**********************************
extern KEY *apupdo_1(void);
extern KEY *dpupdo_1(void);
extern KEY *sumrmdo_1(void);
***********************************/
extern KEY *delseriesdo_1(void);
extern KEY *configdo_1(void);
extern KEY *repartndo_1(void);

/* This is the tape_svc program registration */
#define TAPEPROG ((uint32_t)0x20000612)  /* 536872466 */
#define TAPEVERS ((uint32_t)1)
#define READDO ((uint32_t)1)
#define WRITEDO ((uint32_t)2)
#define TAPERESPREADDO ((uint32_t)3)
#define TAPERESPWRITEDO ((uint32_t)4)
#define TAPERESPROBOTDO ((uint32_t)5)
#define TAPERESPROBOTDOORDO ((uint32_t)6)
#define IMPEXPDO ((uint32_t)7)
#define TAPETESTDO ((uint32_t)8)
#define ONOFFDO ((uint32_t)9)
#define DRONOFFDO ((uint32_t)10)
#define ROBOTONOFFDO ((uint32_t)11)
#define JMTXTAPEDO ((uint32_t)12)
#define EXPCLOSEDO ((uint32_t)13)
#define TAPENOPDO ((uint32_t)14)
#define CLNTGONE ((uint32_t)15)

extern KEY *readdo_1(void);
extern KEY *writedo_1(void);
extern KEY *taperespreaddo_1(void);
extern KEY *taperespwritedo_1(void);
extern KEY *taperesprobotdo_1(void);
extern KEY *taperesprobotdoordo_1(void);
extern KEY *impexpdo_1(void);
extern KEY *tapetestdo_1(void);
extern KEY *onoffdo_1(void);
extern KEY *dronoffdo_1(void);
extern KEY *robotonoffdo_1(void);
extern KEY *jmtxtapedo_1(void);
extern KEY *expclosedo_1(void);
extern KEY *tapenopdo_1(void);
extern KEY *clntgone_1(void);

/* This is the SUM client API code response handling registration */
#define RESPPROG ((uint32_t)0x20000613)  /* 536872467 */
#define RESPVERS ((uint32_t)1)
#define RESPDO ((uint32_t)1)
#define RESPDOARRAY ((uint32_t)2)
#define RESULT_PEND 32		/* returned by clnt_call GETDO request 
				   when storage unit is off line */
extern KEY *respdo_1(KEY *params);

/* This is the tapearc program registration */
#define TAPEARCPROG ((uint32_t)0x20000614) /* 536872468 */
#define TAPEARCVERS ((uint32_t)1)
#define TAPEARCVERS0 ((uint32_t)2)
#define TAPEARCVERS1 ((uint32_t)3)
#define TAPEARCVERS2 ((uint32_t)4)
#define TAPEARCVERS3 ((uint32_t)5)
#define TAPEARCVERS4 ((uint32_t)6)
#define TAPEARCVERS5 ((uint32_t)7)
#define TAPEARCVERS6 ((uint32_t)8)
#define TAPEARCVERS7 ((uint32_t)9)
#define TAPEARCVERS8 ((uint32_t)10)
#define TAPEARCDO ((uint32_t)1)

extern KEY *tapearcdo_1(KEY *params);

/* This is the drive0_svc program registration */
#define DRIVE0PROG ((uint32_t)0x20000615)  /* 536872469 */
#define DRIVE0VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

extern KEY *readdrvdo_1(KEY *params);
extern KEY *writedrvdo_1(KEY *params);

/* This is the drive1_svc program registration */
#define DRIVE1PROG ((uint32_t)0x20000616)
#define DRIVE1VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive2_svc program registration */
#define DRIVE2PROG ((uint32_t)0x20000617)
#define DRIVE2VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive3_svc program registration */
#define DRIVE3PROG ((uint32_t)0x20000618)
#define DRIVE3VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive4_svc program registration */
#define DRIVE4PROG ((uint32_t)0x20000619)
#define DRIVE4VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive5_svc program registration */
#define DRIVE5PROG ((uint32_t)0x2000061a)
#define DRIVE5VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive6_svc program registration */
#define DRIVE6PROG ((uint32_t)0x2000061b)
#define DRIVE6VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive7_svc program registration */
#define DRIVE7PROG ((uint32_t)0x2000061c)
#define DRIVE7VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive8_svc program registration */
#define DRIVE8PROG ((uint32_t)0x2000061d)
#define DRIVE8VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive9_svc program registration */
#define DRIVE9PROG ((uint32_t)0x2000061e)
#define DRIVE9VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive10_svc program registration */
#define DRIVE10PROG ((uint32_t)0x2000061f)
#define DRIVE10VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the drive11_svc program registration */
#define DRIVE11PROG ((uint32_t)0x20000620)
#define DRIVE11VERS ((uint32_t)1)
#define READDRVDO ((uint32_t)1)
#define WRITEDRVDO ((uint32_t)2)

/* This is the robot0_svc program registration */
#define ROBOT0PROG ((uint32_t)0x20000627)
#define ROBOT0VERS ((uint32_t)1)
#define ROBOTDO ((uint32_t)1)
#define ROBOTDOORDO ((uint32_t)2)

extern KEY *robotdo_1(KEY *params);
extern KEY *robotdoordo_1(KEY *params);

/* This is the robot1_svc program registration */
#define ROBOT1PROG ((uint32_t)0x20000628)
#define ROBOT1VERS ((uint32_t)1)
#define ROBOTDO ((uint32_t)1)

/* This is the sum_rm program registration */
/* OBSOLETE no longer used */
#define SUMRMPROG ((uint32_t)0x20000629)
#define SUMRMVERS ((uint32_t)1)
/*#define RMRESPDO ((uint32_t)1)*/
/*extern KEY *rmrespdo_1();*/

/* This is the sum_pe_svc program registration */
#define SUMPEPROG ((uint32_t)0x2000062a) 
#define SUMPEVERS ((uint32_t)1)
#define SUMPEVERS2 ((uint32_t)2)
#define SUMPEDO ((uint32_t)1)
#define SUMPEACK ((uint32_t)2)
extern KEY *sumpedo_1(KEY *params);
extern KEY *sumpeack_1(KEY *params);

/* This is the pe/peq program registration for answers from sum_pe_svc */
#define PEPEQPROG ((uint32_t)0x2000062b)
#define PEPEQVERS ((uint32_t)1)
#define PEPEQRESPDO ((uint32_t)1)
extern KEY *pepeqdo_1(KEY *params);

/* This is the sum_export_svc program registration */
#define SUMEXPROG ((uint32_t)0x2000062c)
#define SUMEXVERS ((uint32_t)1)
#define SUMEXVERS2 ((uint32_t)2)
#define SUMEXDO ((uint32_t)1)
#define SUMEXACK ((uint32_t)2)
extern KEY *sumexdo_1(KEY *params);
extern KEY *sumexack_1(KEY *params);

/* This is the SUM_export() registration for answers from sum_export_svc */
#define REMSUMPROG ((uint32_t)0x2000062d)
#define REMSUMVERS ((uint32_t)1)
#define REMSUMRESPDO ((uint32_t)1)

/* This is the jmtx program registration */
#define JMTXPROG ((uint32_t)0x2000062e) /* 536872494 */
#define JMTXVERS ((uint32_t)1)
#define JMTXDO ((uint32_t)1)
extern KEY *jmtxdo_1(KEY *params);

/* This is the sum_ping program registration */
#define SUMPINGPROG ((uint32_t)0x2000062f) /* 536872495 */
#define SUMPINGVERS ((uint32_t)1)
#define SUMPINGDO ((uint32_t)1)

#if defined(SUMS_USEMTSUMS) && SUMS_USEMTSUMS
typedef int MSUMSCLIENT_t;
#endif

//NOTE: Must be client handles for MAXNUMSUM (defined in SUM.h) servers
typedef struct SUM_struct
{
  SUMID_t uid;
  CLIENT *cl;            /* client handle for calling sum_svc */
  CLIENT *clopen;           /* client handle for calling sum_svc open */
  CLIENT *clopen1;          /* client handle for calling sum_svc open */
  CLIENT *clopen2;          /* client handle for calling sum_svc open */
  CLIENT *clopen3;          /* client handle for calling sum_svc open */
  CLIENT *clopen4;          /* client handle for calling sum_svc open */
  CLIENT *clopen5;          /* client handle for calling sum_svc open */
  CLIENT *clopen6;          /* client handle for calling sum_svc open */
  CLIENT *clopen7;          /* client handle for calling sum_svc open */
  CLIENT *clalloc;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc1;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc2;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc3;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc4;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc5;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc6;       /* client handle for calling sum_svc allocate */
  CLIENT *clalloc7;       /* client handle for calling sum_svc allocate */
  CLIENT *clget;         /* client handle for calling sum_svc get */
  CLIENT *clget1;        /* client handle for calling sum_svc get */
  CLIENT *clget2;        /* client handle for calling sum_svc get */
  CLIENT *clget3;        /* client handle for calling sum_svc get */
  CLIENT *clget4;        /* client handle for calling sum_svc get */
  CLIENT *clget5;        /* client handle for calling sum_svc get */
  CLIENT *clget6;        /* client handle for calling sum_svc get */
  CLIENT *clget7;        /* client handle for calling sum_svc get */
  CLIENT *clput;         /* client handle for calling sum_svc put */
  CLIENT *clput1;        /* client handle for calling sum_svc put */
  CLIENT *clput2;        /* client handle for calling sum_svc put */
  CLIENT *clput3;        /* client handle for calling sum_svc put */
  CLIENT *clput4;        /* client handle for calling sum_svc put */
  CLIENT *clput5;        /* client handle for calling sum_svc put */
  CLIENT *clput6;        /* client handle for calling sum_svc put */
  CLIENT *clput7;        /* client handle for calling sum_svc put */
#if !defined(SUMS_USEMTSUMS) || !SUMS_USEMTSUMS
  CLIENT *clinfo;        /* client handle for calling sum_svc info */
  CLIENT *clinfo1;       /* client handle for calling sum_svc info */
  CLIENT *clinfo2;       /* client handle for calling sum_svc info */
  CLIENT *clinfo3;       /* client handle for calling sum_svc info */
  CLIENT *clinfo4;       /* client handle for calling sum_svc info */
  CLIENT *clinfo5;       /* client handle for calling sum_svc info */
  CLIENT *clinfo6;       /* client handle for calling sum_svc info */
  CLIENT *clinfo7;       /* client handle for calling sum_svc info */
#endif
  CLIENT *cldelser;      /* client handle for calling sum_svc del series */
  SUM_info_t *sinfo;	 /* info from sum_main for SUM_info() call */
  int debugflg;		 /* verbose debug mode if set */
  int mode;              /* bit map of various modes */
  int tdays;             /* touch days for retention */
  int group;             /* group # for the given dataseries */
  int storeset;          /* assign storage from JSOC, DSDS, etc. Default JSOC */
  int status;		 /* return status on calls. 1 = error, 0 = success */
  int numSUM;		 /* returned from CONFIGDO call in SUM_open() */
  double bytes;
  char *dsname;          /* dataseries name */
  char *username;	 /* user's login name */
  char *history_comment; /* history comment string */
  int reqcnt;            /* # of entries in arrays below */
  uint64_t *dsix_ptr;    /* ptr to array of dsindex uint64_t */
  char **wd;		 /* ptr to array of char * */
#if defined(SUMS_USEMTSUMS) && SUMS_USEMTSUMS
  MSUMSCLIENT_t mSumsClient;   /* A handle to sumsd.py (a socket file descriptor actually ) */
  struct Pickler_struct *pickler; /* An OPAQUE handle to stuff that needs to be decremented when we tear-down Py environment. */
#endif
} SUM_t;

typedef struct SUMEXP_struct
{
  SUMID_t uid;
  int reqcnt;		/* # of entries in arrays below */
  uint32_t port;	/* port #, -P, to use in scp command */
  char *cmd;            /* copy cmd (eg, scp, hpn-scp) */
  char *host;		/* hostname target of scp call */
  char **src;		/* ptr to char * of source dirs */
  char **dest;		/* ptr to char * of destination dirs */
} SUMEXP_t;

/* SUMID/SUM assignment table. One of these is put onto the sum_hdr pointer
 * each time a single client registers (opens) with sum_svc, and removed when 
 * it deregisters (closes).
*/
struct sumopened {
  struct sumopened *next;
  SUMID_t uid;
  SUM_t *sum;
  char user[16];
};
typedef struct sumopened SUMOPENED;

/* SUMID/Offcnt assignment table. An entry is made by readdo_1() in 
 * tape_svc_proc.c when a SUM_get() is made by a user and one or more storge
 * units are offline. This keeps track of unique tapeids and file numbers 
 * to read. Also, whenever a tape read completes, the offcnt is incremented
 * until the uniqcnt is reach, at which point a response
 * is finnally sent to sum_svc that the SUM_get() is complete.
*/
struct sumoffcnt {
  struct sumoffcnt *next;
  SUMID_t uid;
  int offcnt;
  int uniqcnt;
  char *tapeids[MAXSUMREQCNT];
  int tapefns[MAXSUMREQCNT];
  int reqofflinenum[MAXSUMREQCNT];
  uint64_t dsix[MAXSUMREQCNT];
  uint32_t sprog;		//added 22May2012
};
typedef struct sumoffcnt SUMOFFCNT;
 

/* Tape queue assignment table. One of these is put onto the tq_rd_hdr or
 * tq_wrt_hdr pointer each time tape_svc gets a tape read or write request.
*/
struct tq {
  struct tq *next;
  KEY *list;
  SUMID_t uid;
  uint32_t spare;
  uint64_t ds_index;
  char *tapeid;
  char *username;
  int filenum;
};
typedef struct tq TQ;

/* Partition assignment table. For working directory assignments made
 * by dsds_svc, there will be a number of these tables linked onto one of
 * the pahdr_xx pointers.
*/
struct padata {
  struct padata *next;
  char *wd;
  char *effective_date;
  uint64_t sumid;
  double bytes;
  int status;
  int archsub;          /* archive pend substatuses */
  int group_id;         /* for grouping in tape archives */
  int safe_id;          /* for grouping in safe tape archives */
  uint64_t ds_index;
};
typedef struct padata PADATA;

/* Partition definition table. One for each dedicated SUM partition.
 * Initialized by sum_svc from the sum_partn_avail data base table.
 * NOTE: pds_set_prime was added to sum_partn_avail on 7/23/2012.
 * It may not be added to the NetDRMS DBs. They use sum_rm instead
 * of sum_rm_[0,1,2] which needs the new pds_set_prime.
*/
struct partition {
  char *name;           /* name of the partition */
  double bytes_total;   /* total number of bytes of the partition */
  double bytes_left;    /* bytes unassigned */
  double bytes_alloc;   /* bytes allocated by DS_Allocate() */
  int pds_set_num;      /* SUM set the part. belongs to. aka sum_set_num */
			/* This can be taken offline (-1) by sum_rm */
  int pds_set_prime;	/* used by sum_rm to restore pds_set_num from -1 */
};
typedef struct partition PART;

/* Pe/uid assignment table. One of these is put onto the peuid_hdr pointer
 * each time a pe registers (opens) with dsds_svc, and removed when pe
 * deregisters (closes).
 * !!TBD see how this fits in with SUMS
*/
struct peuid {
  struct peuid *next;
  uint64_t uid;
  int petid;
};
typedef struct peuid PEUID;


SUM_t *SUM_open(char *server, char *db, int (*history)(const char *fmt, ...));
int SUM_shutdown(int query, int (*history)(const char *fmt, ...));
int SUM_close(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_get(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_put(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_archSU(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_alloc(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_alloc2(SUM_t *sum, uint64_t sunum, int (*history)(const char *fmt, ...));
int SUM_poll(SUM_t *sum);
int SUM_wait(SUM_t *sum);
int SUM_delete_series(char *filename, char *seriesname, int (*history)(const char *fmt, ...));
int SUM_export(SUMEXP_t *sumexp, int (*history)(const char *fmt, ...));
#if defined(SUMS_USEMTSUMS) && SUMS_USEMTSUMS
int SUM_infoArray(SUM_t *sums, uint64_t *sunums, int reqcnt, int (*history)(const char *fmt, ...));
void SUM_infoArray_free(SUM_t *sums);
#else
int SUM_info(SUM_t *sum, uint64_t sunum, int (*history)(const char *fmt, ...));
int SUM_infoEx(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_infoArray(SUM_t *sum, uint64_t *dxarray, int reqcnt, int (*history)(const char *fmt, ...));
void SUM_infoEx_free(SUM_t *sum);
void SUM_infoArray_free(SUM_t *sum);
#endif
int SUM_nop(SUM_t *sum, int (*history)(const char *fmt, ...));
int SUM_repartn(SUM_t *sum, int (*history)(const char *fmt, ...));

int NC_PaUpdate(char *wd, uint64_t uid, double bytes, int status, int archsub, char *eff_date, int gpid, int sid, uint64_t ds_index, int flg, int commit);
SUMID_t SUMLIB_Open(void);
SUMID_t sumrpcopen_1(KEY *argp, CLIENT *clnt, int (*history)(const char *fmt, ...));
void setsumopened (SUMOPENED **list, SUMID_t uid, SUM_t *sum, char *user);
SUMOPENED *getsumopened (SUMOPENED *list, SUMID_t uid);
void remsumopened (SUMOPENED **list, SUMID_t uid);
SUMOFFCNT *setsumoffcnt (SUMOFFCNT **list, SUMID_t uid, int offcnt);
SUMOFFCNT *getsumoffcnt (SUMOFFCNT *list, SUMID_t uid);
void remsumoffcnt (SUMOFFCNT **list, SUMID_t uid);
TQ *delete_q_rd_front(void);
TQ *delete_q_wrt_front(void);
TQ *delete_q_rd(TQ *p);
TQ *delete_q_wrt(TQ *p);
TQ *q_entry_make(KEY *list, SUMID_t uid, char *tapeid, int filenum, char *user, uint64_t dsix);
void tq_entry_rd_dump(char *user);
void insert_tq_entry_rd_sort(TQ *p);
void insert_tq_entry_rd(TQ *p);
void insert_tq_entry_wrt(TQ *p);
PADATA *getpadata(PADATA *list, char *wd, uint64_t sumid);
PADATA *getpauid(PADATA *list, uint64_t uid);
PADATA *getpawd(PADATA *list, char *wd);
PADATA *getpanext(PADATA *list);
PADATA *NC_PaRequest_AP(int groupset);
PADATA *NC_PaRequest_AP_60d(void);
int DS_ConnectDB (char *dbname);
int DS_DisConnectDB(void);
int DS_ConnectDB_Q (char *dbname);
int DS_DisConnectDB_Q(void);
int DS_DataRequest(KEY *params, KEY **results);
int DS_PavailRequest(void);
int DS_PallocRequest(void);
int DS_PallocClean(void);
int DS_RmDo(double *bytesdel);
int DS_RmNow(char *wd, uint64_t sumid, double bytes, char *effdate, uint64_t ds_index, int archsub, double *rmbytes);
int DS_RmDoX(char *name, double bytesdel);
int DS_RmNowX(char *wd, uint64_t sumid, double bytes, char *effdate, uint64_t ds_index, int archsub, double *rmbytes);
int DS_Rm_Commit(void);
int rmdirs(char *wd, char *root);
int SUM_Main_Update (KEY *params, KEY **results);
//int SUM_Main_Update (KEY *params);
int SUMLIB_Close(KEY *params);
int SUMLIB_TapeState(char *tapeid);
int SUM_StatOffline(uint64_t ds_index);
int SUMLIB_TapeClose(char *tapeid);
int SUMLIB_TapeActive(char *tapeid);
int SUMLIB_TapeCatalog(char *tapeid);
int SUMLIB_MainTapeUpdate(KEY *params); 
int SUMLIB_EffDateUpdate(char *tapeid, int operation);
int SUMLIB_MD5info(char *tapeid);
int SUMLIB_SafeTapeUpdate(char *suname, char *tapeid, int tapefn, char *tapedate); 
int DS_SumMainDelete(uint64_t ds_index);
int SUM_StatOnline(uint64_t ds_index, char *newwd);
int DS_DataRequest_WD(KEY *params, KEY **results);
int SUMLIB_TapeUpdate(char *tapeid, int tapenxtfn, uint64_t tellblock, double totalbytes);
int SUMLIB_TapeFilenumber(char *tapeid);
#if defined(SUMS_TAPE_AVAILABLE) && SUMS_TAPE_AVAILABLE
int SUMLIB_TapeFindGroup(int group, double bytes, TAPE *tape);
#endif
int SUMLIB_PavailGet(double bytes, int pds_set, uint64_t uid, uint64_t sunum, KEY **results);
int SUMLIB_PavailUpdate(char *name, double bytes);
int SUMLIB_PavailOff(char *name);
int SUMLIB_PavailOn(char *name, int setnum);
int SUMLIB_DelSeriesSU(char *file, char *series); 
int SUMLIB_InfoGet(uint64_t sunum , KEY **results);


void setpeuid(PEUID **list, uint64_t uid, int petid);
void updpadata (PADATA **list, char *wd, uint64_t sumid, char *eff_date);
PEUID *getpeuid(PEUID *list, uint64_t uid);
PEUID *getpeuidnext(PEUID *list);
void rempeuid(PEUID **list, uint64_t uid);
void setpadata(PADATA **list, char *wd, uint64_t sumid, double bytes,
int stat, int substat, char *eff_date,
int group_id, int safe_id, uint64_t ds_index);
void setpadatar(PADATA **list, char *wd, uint64_t sumid, double bytes,
int stat, int substat, char *eff_date,
int group_id, int safe_id, uint64_t ds_index);
int tape_inventory(int sim, int catalog);
int robot_verify(char *action, int slot, int slotordrive);
void uidpadata(PADATA *new, PADATA **start, PADATA **end);
void remuidpadata(PADATA **start, PADATA **end, char *wd, uint64_t sumid);
void rempadata(PADATA **list, char *wd, uint64_t sumid);
char *get_effdate(int plusdays);
char *get_datetime(void);
void write_time(void);
void send_ack(void);
CLIENT *set_client_handle(uint32_t prognum, uint32_t versnum);
double du_dir(char *wd);

#endif

