/* dsdsapi.h - Defines DSDS API. */
#ifndef _DSDSAPI_H
#define _DSDSAPI_H

#include "drms_types.h"

#define kJSOC_MACHINE "JSOC_MACHINE"
#define kLIBDSDS "libdsds.so"
#define kDSDS_SERIES_NUM "series_num"
#define kDSDS_DS "ds"
#define kDSDS_RN "rn"
#define kDSDS_PROGTOKEN "prog:"
#define kDSDS_NSPREFIX "dsdsing"

#define kDSDS_MaxHandle 64

typedef enum kDSDS_Stat_enum
{
   kDSDS_Stat_Success = 0,   /* No errors */
   kDSDS_Stat_CantReadProcLink,
   kDSDS_Stat_CantOpenLibrary,
   kDSDS_Stat_NoEnvironment,  /* Attempt to access DSDS when 
                                 access prohibited */
   kDSDS_Stat_NoSOI,	      /* Attempt to use libsoi.so, 
                                 but could not open it */
   kDSDS_Stat_MissingAPI,     /* No entry point for requested DSDS API */
   kDSDS_Stat_APIRetErr,      /* The called function returned an error */
   kDSDS_Stat_TypeErr,	      /* Error converting void * 
                                 to DRMS_Type_Value_t */
   kDSDS_Stat_PeqError,	      /* Error creating SOI keylist */
   kDSDS_Stat_MalformedKey,   /* Invalid SOI level key generated by peq */
   kDSDS_Stat_NoMemory,	      /* Error allocating memory */
                              /* The Alberto Gonzalez defense */
   kDSDS_Stat_InvalidRank,    /* DSDS data has too many dimensions for DRMS */
   kDSDS_Stat_InvalidParams,  /* Bad params passed into a 
                                 libdsds.so entry point */
   kDSDS_Stat_InvalidHandle,  /* Bad handle passed into a 
                                 libdsds.so entry point */
   kDSDS_Stat_InvalidFITS,    /* Not a fits file */
   kDSDS_Stat_UnkFITSpath,    /* The fits file path was not in vds->filename and 
                               * not in sds->filename */
   kDSDS_Stat_DSDSOffline     /* DSDS data are in SUMS, but offline */
				
} kDSDS_Stat_t;

typedef const char *DSDS_Handle_t;
typedef DSDS_Handle_t *DSDS_pHandle_t;

typedef struct DSDS_KeyList_struct
{
  DRMS_Keyword_t *elem;
  struct DSDS_KeyList_struct *next;
} DSDS_KeyList_t;


/* External API (available to su and non-su) */
#define kDSDS_Segment "dsds_data"

void *DSDS_GetFPtr(void *hDSDS, const char *symbol);
int DSDS_IsDSDSSpec(const char *spec);
int DSDS_IsDSDSPort(const char *query);
int DSDS_GetDSDSParams(DRMS_SeriesInfo_t *si, char *out);
int DSDS_SetDSDSParams(void *hDSDS, DRMS_SeriesInfo_t *si, DSDS_Handle_t in);
void *DSDS_GetLibHandle(const char *libname, kDSDS_Stat_t *status);
static inline const char *DSDS_GetNsPrefix()
{
   return kDSDS_NSPREFIX;
}

/* Internal API (available to su only) */
#define kDSDS_DSDS_OPEN_RECORDS "DSDS_open_records"
#define kDSDS_DSDS_FREE_KEYLIST "DSDS_free_keylist"
#define kDSDS_DSDS_FREE_KEYLISTARR "DSDS_free_keylistarr"
#define kDSDS_DSDS_FREE_SEG "DSDS_free_seg"
#define kDSDS_DSDS_FREE_SEGARR "DSDS_free_segarr"
#define kDSDS_DSDS_STEAL_SEGINFO "DSDS_steal_seginfo"
#define kDSDS_DSDS_SEGMENT_READ "DSDS_segment_read"
#define kDSDS_DSDS_FREE_ARRAY "DSDS_free_array"
#define kDSDS_DSDS_HANDLE_TODESC "DSDS_handle_todesc"
#define kDSDS_DSDS_FREE_HANDLE "DSDS_free_handle"
#define kDSDS_DSDS_READ_FITSHEADER "DSDS_read_fitsheader"

typedef long long (*pDSDSFn_DSDS_open_records_t)(const char *dsspec, 
						 char *drmsSeries,
						 DSDS_pHandle_t hparams,
						 DSDS_KeyList_t ***keylistarr,
						 DRMS_Segment_t **segarr,
						 kDSDS_Stat_t *stat);
typedef void (*pDSDSFn_DSDS_free_keylist_t)(DSDS_KeyList_t **keylist);
typedef void (*pDSDSFn_DSDS_free_keylistarr_t)(DSDS_KeyList_t ***keylistarr, 
					       int n);
typedef void (*pDSDSFn_DSDS_free_seg_t)(DRMS_Segment_t **seg);
typedef void (*pDSDSFn_DSDS_free_segarr_t)(DRMS_Segment_t **segarr,
					   int n);
typedef void (*pDSDSFn_DSDS_steal_seginfo_t)(DRMS_Segment_t *thief, DRMS_Segment_t *victim);
typedef DRMS_Array_t *(*pDSDSFn_DSDS_segment_read_t)(char *paramsDesc, 
						     int ds, 
						     int rn, 
						     const char *filename,
						     kDSDS_Stat_t *stat);
typedef void (*pDSDSFn_DSDS_free_array_t)(DRMS_Array_t **arr);
typedef int (*pDSDSFn_DSDS_handle_todesc_t)(DSDS_Handle_t handle, 
					    char *desc, 
					    kDSDS_Stat_t *stat);
typedef void (*pDSDSFn_DSDS_free_handle_t)(DSDS_pHandle_t pHandle);
typedef int (*pDSDSFn_DSDS_read_fitsheader_t)(const char *file,
					      DSDS_KeyList_t **keylist,
					      DRMS_Segment_t **seg,
					      const char *segname,
					      kDSDS_Stat_t *stat);

#endif /* _DSDSAPI_H */
