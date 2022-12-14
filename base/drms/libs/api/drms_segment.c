/*
 *  drms_segment.c                                              2007.11.26
 *
 *  functions defined:
 *      drms_free_template_segment_struct
 *      drms_free_segment_struct
 *      drms_copy_segment_struct
 *      drms_create_segment_prototypes
 *      drms_template_segments
 *      drms_segment_print
 *      drms_segment_size
 *      drms_segment_setdims
 *      drms_segment_getdims
 *      drms_segment_createinfocon
 *      drms_segment_destroyinfocon
 *      drms_segment_filename
 *      drms_delete_segmentfile
 *      drms_segment_lookup
 *      drms_segment_lookupnum
 *      drms_segment_read
 *      drms_segment_readslice
 *      drms_segment_write
 *      drms_segment_write_from_file
 *      drms_segment_setblocksize
 *      drms_segment_getblocksize
 *      drms_segment_autoscale
 *      drms_segment_segsmatch
 */

//#define DEBUG

#include "drms.h"
#include "drms_priv.h"
#include <float.h>
#include <dlfcn.h>
#include "xmem.h"
#include "drms_dsdsapi.h"
#include "cfitsio.h"
#include "fitsexport.h"
#include "drms_fitsrw.h"


/******** helper functions that don't get exported as part of API ********/
static DRMS_Segment_t * __drms_segment_lookup(DRMS_Record_t *rec,
					      const char *segname, int depth);

static int drms_segment_set_const(DRMS_Segment_t *seg);
static int drms_segment_checkscaling (const DRMS_Array_t* arr, double bzero,
				      double bscale);

/*
   Recursive segment lookup that follows linked segment to
   their destination until a non-link segment is reached. If the
   recursion depth exceeds DRMS_MAXLINKDEPTH it is assumed that there
   is an erroneous link cycle, an error message is written to stderr,
   and a NULL pointer is returned.
*/
static DRMS_Segment_t * __drms_segment_lookup(DRMS_Record_t *rec,
					      const char *segname, int depth)
{
    int stat;
    DRMS_Segment_t *segment;
    DRMS_Segment_t *rv = NULL;

    segment = hcon_lookup_lower(&rec->segments, segname);
    if (segment!=NULL && depth<DRMS_MAXLINKDEPTH )
    {
        if (segment->info->islink)
        {
            DRMS_Record_t *linkedRec = NULL;

            linkedRec = drms_link_follow(rec, segment->info->linkname, &stat);
            if (stat)
                rv = NULL;
            else
            {
                rv = __drms_segment_lookup(linkedRec, segment->info->target_seg, depth+1);
            }

            /* Whatever you do, do not free linkedRec here. If it is freed, then the segment returned,
             * which has a reference to linkedRec, will have a pointer to garbage. In fact, the segment
             * returned will be garbage because freeing the containing record frees the segment. */
            return rv;

        }
        else
        {
            return segment;
        }
    }
    if (depth>=DRMS_MAXLINKDEPTH)
        fprintf(stderr, "WARNING: Max link depth exceeded for segment '%s' in "
                "record %lld from series '%s'\n", segment->info->name, rec->recnum,
                rec->seriesinfo->seriesname);

    return NULL;
}

int drms_segment_set_const(DRMS_Segment_t *seg) {
  XASSERT(seg->info->scope == DRMS_CONSTANT &&
	  !seg->info->cseg_recnum);
  DRMS_Record_t *rec = seg->record;
  seg->info->cseg_recnum = rec->recnum;

  // write back to drms_segment table
  char stmt[DRMS_MAXQUERYLEN];
  char *namespace = ns(rec->seriesinfo->seriesname);
  char *lcseries = strdup(rec->seriesinfo->seriesname);

  if (!lcseries)
  {
     free(namespace);
     return DRMS_ERROR_OUTOFMEMORY;
  }

  char *lcsegname = strdup(seg->info->name);

  if (!lcsegname)
  {
     free(lcseries);
     free(namespace);
     return DRMS_ERROR_OUTOFMEMORY;
  }

  strtolower(lcseries);
  strtolower(lcsegname);

  sprintf(stmt, "UPDATE %s." DRMS_MASTER_SEGMENT_TABLE
	  " SET cseg_recnum = %lld WHERE lower(seriesname) = '%s' AND lower(segmentname) = '%s'",
	  namespace, rec->recnum, lcseries, lcsegname);

  free(lcsegname);
  free(lcseries);
  free(namespace);

  if(drms_dms(rec->env->session, NULL, stmt)) {
    fprintf(stderr, "Failed to update drms_segment table for constant segment\n");
    return DRMS_ERROR_QUERYFAILED;
  }
  return DRMS_SUCCESS;
}

int drms_segment_checkscaling (const DRMS_Array_t *a, double zero, double scale) {
  int ret = 1;
  double numz = fabs (a->bzero - zero);
  double nums = fabs (a->bscale - scale);
  double denz = fabs (zero);
  double dens = fabs (scale);

  denz += fabs (a->bzero);
  dens += fabs (a->bscale);

  if ((numz > 1.0e-11 * denz) || (nums > 1.0e-11 * dens)) {
    ret = 0;
  }
  return ret;
}

/****************************** API functions ******************************/
void drms_free_template_segment_struct (DRMS_Segment_t *segment) {
  free (segment->info);
}

void drms_free_segment_struct (DRMS_Segment_t *segment) {
  XASSERT(segment);
  return;
}

void drms_copy_segment_struct(DRMS_Segment_t *dst, DRMS_Segment_t *src)
{
  /* Copy struct. */
  memcpy(dst,src,sizeof(DRMS_Segment_t));
  return;
}

/* returns a pointer to the target's segment container. */
HContainer_t *drms_create_segment_prototypes(DRMS_Record_t *target,
					     DRMS_Record_t *source,
					     int *status)
{
    HContainer_t *ret = NULL;
    DRMS_Segment_t *tSeg = NULL;
    DRMS_Segment_t *sSeg = NULL;

    XASSERT(target != NULL && target->segments.num_total == 0 && source != NULL);

    if (target != NULL && target->segments.num_total == 0 && source != NULL)
    {
        *status = DRMS_SUCCESS;
        HIterator_t hit;
        hiter_new_sort(&hit, &(source->segments), drms_segment_ranksort);

        while ((sSeg = hiter_getnext(&hit)) != NULL)
        {
            if (sSeg->info && strlen(sSeg->info->name) > 0)
            {
                tSeg = hcon_allocslot_lower(&(target->segments), sSeg->info->name);
                XASSERT(tSeg);
                memset(tSeg, 0, sizeof(DRMS_Segment_t));
                tSeg->info = malloc(sizeof(DRMS_SegmentInfo_t));
                XASSERT(tSeg->info);
                memset(tSeg->info, 0, sizeof(DRMS_SegmentInfo_t));

                if (tSeg && tSeg->info)
                {
                    /* record */
                    tSeg->record = target;

                    /* segment info*/
                    memcpy(tSeg->info, sSeg->info, sizeof(DRMS_SegmentInfo_t));

                    /* axis is allocated as static array */
                    memcpy(tSeg->axis, sSeg->axis, sizeof(int) * DRMS_MAXRANK);

                    if (tSeg->info->protocol == DRMS_TAS)
                    {
                        /* blocksize is allocated as static array */
                        memcpy(tSeg->blocksize, sSeg->blocksize, sizeof(int) * DRMS_MAXRANK);
                    }

                    /* copy cparms - compression string */
                    snprintf(tSeg->cparms, sizeof(tSeg->cparms), "%s", sSeg->cparms);

                    /* bzero/bscale */
                    tSeg->bzero = sSeg->bzero;
                    tSeg->bscale = sSeg->bscale;
                }
                else
                {
                    *status = DRMS_ERROR_OUTOFMEMORY;
                }
            }
            else
            {
                *status = DRMS_ERROR_INVALIDSEGMENT;
            }
        }

        hiter_free(&hit);

        if (*status == DRMS_SUCCESS)
        {
            ret = &(target->segments);
        }
    }
    else
    {
        *status = DRMS_ERROR_INVALIDRECORD;
    }

    return ret;
}

/*
   Build the segment part of a dataset template by
   using the query result holding a list of
   (segmentname, segnum, form, scope, type,
   naxis, axis, unit, protocol, description)
   tuples to initialize the array of segment descriptors.
*/
int drms_template_segments(DRMS_Record_t *template)
{
  DRMS_Env_t *env;
  int i,n,status = DRMS_NO_ERROR;
  char buf[1024], query[DRMS_MAXQUERYLEN], *p, *q;
  DRMS_Segment_t *seg;
  DB_Binary_Result_t *qres;
  char *lcseries = strdup(template->seriesinfo->seriesname);

  if (!lcseries)
  {
     status = DRMS_ERROR_OUTOFMEMORY;
     goto bailout;
  }

  strtolower(lcseries);

  env = template->env;

  /* Initialize container structure. */
  hcon_init(&template->segments, sizeof(DRMS_Segment_t), DRMS_MAXSEGNAMELEN,
            (void (*)(const void *)) drms_free_segment_struct,
		    (void (*)(const void *, const void *)) drms_copy_segment_struct);

  /* Get segment definitions and add to template. */
  char *namespace = ns(template->seriesinfo->seriesname);
  sprintf(query, "select segmentname, segnum, scope, type, "
	  "naxis, axis, unit, protocol, description, "
	  "islink, linkname, targetseg, cseg_recnum from %s.%s where "
	  "lower(seriesname) = '%s' order by segnum",
	  namespace, DRMS_MASTER_SEGMENT_TABLE, lcseries);
  free(lcseries);
  free(namespace);

  if (env->verbose)
  {
     fprintf(stdout, "Template Segment Query: %s\n", query);
  }

  if ((qres = drms_query_bin(env->session, query)) == NULL)
    return DRMS_ERROR_QUERYFAILED; /* SQL error. */

#ifdef DEBUG
  printf("#0\n");
  db_print_binary_result(qres);
#endif

  if (qres->num_rows>0 && qres->num_cols != 13 )
  {
    status = DRMS_ERROR_BADFIELDCOUNT;
    goto bailout;
  }
  for (i = 0; i<(int)qres->num_rows; i++)
  {
    /* Name */
    db_binary_field_getstr(qres, i, 0, 1024, buf);
    seg = hcon_allocslot_lower(&template->segments, buf);
    memset(seg,0,sizeof(DRMS_Segment_t));
    seg->info = malloc(sizeof( DRMS_SegmentInfo_t));
    XASSERT(seg->info);
    memset(seg->info,0,sizeof(DRMS_SegmentInfo_t));
    seg->record = template;
    strcpy(seg->info->name, buf);
    /* Number */
    seg->info->segnum = db_binary_field_getint(qres, i, 1);
    seg->info->islink = db_binary_field_getint(qres, i, 9);
    if (seg->info->islink) {
      /* Link segment */
      db_binary_field_getstr(qres, i, 10, sizeof(seg->info->linkname),seg->info->linkname);
      db_binary_field_getstr(qres, i, 11, sizeof(seg->info->target_seg),seg->info->target_seg);
      seg->info->scope = DRMS_VARIABLE;
      seg->info->type = DRMS_TYPE_INT;
      seg->info->unit[0] = '\0';
      seg->info->protocol = DRMS_GENERIC;
    } else {
      /* Simple segment */
      /* Scope */
      db_binary_field_getstr(qres, i, 2, 1024, buf);
      seg->info->cseg_recnum = 0;
      if (!strcmp(buf, "constant")) {
	seg->info->scope = DRMS_CONSTANT;
	seg->info->cseg_recnum = db_binary_field_getlonglong(qres, i, 12);
      }
      else if (!strcmp(buf, "variable"))
	seg->info->scope = DRMS_VARIABLE;
      else if (!strcmp(buf, "vardim"))
	seg->info->scope = DRMS_VARDIM;
      else
	{
	  printf("ERROR: Invalid segment scope specifier '%s'\n",buf);
	  goto bailout;
	}
      /* Type */
      db_binary_field_getstr(qres, i, 3, 1024,buf);
      seg->info->type  = drms_str2type(buf);
      /* Unit */
      db_binary_field_getstr(qres, i, 6, DRMS_MAXUNITLEN, seg->info->unit);
      /* Protocol */
      db_binary_field_getstr(qres, i, 7, 1024, buf);
      seg->info->protocol = drms_str2prot(buf);
    }
    /* Naxis */
    seg->info->naxis = db_binary_field_getint(qres, i, 4);
    /* Axis */
    db_binary_field_getstr(qres, i, 5, 1024,buf);
    n = 0;
    p = buf;
    /* Extract the axis dimensions (and in case of the TAS protocol
       block sizes from a copy separated list. */
    while(*p)
      {
	XASSERT(n<2*seg->info->naxis);
	while(!isdigit(*p))
	  ++p;
	q = p;
	while(isdigit(*p))
	  ++p;
	*p++ = 0;
	if (n<seg->info->naxis)
	  seg->axis[n] = atoi(q);
	else
	  seg->blocksize[n - seg->info->naxis] = atoi(q);
	n++;
      }
    if (seg->info->protocol!=DRMS_TAS)
      {
	XASSERT(n==seg->info->naxis);
	memcpy(seg->blocksize,seg->axis,n*sizeof(int));
      }
    else
      {
	XASSERT(n==2*seg->info->naxis);
      }

    /* filename */
    seg->filename[0] = '\0';
    /* Comment */
    db_binary_field_getstr(qres, i, 8, DRMS_MAXCOMMENTLEN, seg->info->description);
  }
#ifdef DEBUG
  printf("#4\n");
  db_print_binary_result(qres);
#endif
  db_free_binary_result(qres);
  return DRMS_SUCCESS;

 bailout:
  db_free_binary_result(qres);
  return status;
}



/* Print the fields of a keyword struct to stdout. */
void drms_segment_print(DRMS_Segment_t *seg)
{
  drms_segment_fprint(stdout, seg);
}


/* Prints the fields of a segment struct to file "keyfile". */
void drms_segment_fprint(FILE *keyfile, DRMS_Segment_t *seg)
{
  int i;
  const int fieldwidth=13;

  fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "name", seg->info->name);
  fprintf(keyfile, "\t%-*s:\t%d\n", fieldwidth, "segnum", seg->info->segnum);
  fprintf(keyfile, "\t%-*s:\t%s\n", fieldwidth, "description", seg->info->description);
  if (seg->info->islink) {
    fprintf(keyfile, "\t%-*s:\t%s\n", fieldwidth, "linkname", seg->info->linkname);
    fprintf(keyfile, "\t%-*s:\t%s\n", fieldwidth, "target segment", seg->info->target_seg);
  } else {
    switch(seg->info->scope)
      {
      case DRMS_CONSTANT:
	fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "scope", "CONSTANT");
	break;
      case DRMS_VARIABLE:
	fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "scope", "VARIABLE");
	break;
      case DRMS_VARDIM:
	fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "scope", "VARIABLE DIMENSION");
	break;
      default:
	fprintf(keyfile, "\t%-*s:\t%s %d\n", fieldwidth, "scope", "Illegal value",
	       (int)seg->info->scope);
      }
    fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "unit", seg->info->unit);
    fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth+9, "type",
	   drms_type2str(seg->info->type));

    /* Protocol info. */
    const char *protstr = drms_prot2str(seg->info->protocol);
    if (protstr)
    {
       fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "protocol", protstr);
    }
    else
    {
       fprintf(keyfile, "\t%-*s:\t%s %d\n", fieldwidth, "protocol", "Illegal value",
	       (int)seg->info->protocol);
    }

    if (strlen(seg->filename)) {
      fprintf(keyfile, "\t%-*s:\t'%s'\n", fieldwidth, "filename", seg->filename);
    }
  }
  /* Array info. */
  fprintf(keyfile, "\t%-*s:\t%d\n", fieldwidth+9, "naxis", seg->info->naxis);
  for (i=0; i<seg->info->naxis; i++)
  {
    fprintf(keyfile, "\t%-*s[%2d]:\t%d\n", fieldwidth+5, "axis", i,
	   seg->axis[i]);
  }

}


/* Return segment size in bytes. */
long long drms_segment_size(DRMS_Segment_t *seg, int *status)
{
  int i;
  long long size;

  size = 1;
  for (i=0; i<seg->info->naxis; i++)
    size *= seg->axis[i];
  if (seg->info->type == DRMS_TYPE_STRING)
    size = size*sizeof(char *);
  else
    size *= drms_sizeof(seg->info->type);
  if (status)
    *status = DRMS_SUCCESS;
  return size;
}

int drms_segment_setdims(DRMS_Segment_t *seg, DRMS_SegmentDimInfo_t *di)
{
   int status = DRMS_SUCCESS;

   if (seg && di)
   {
      seg->info->naxis = di->naxis;
      memcpy(seg->axis, di->axis, sizeof(int) * di->naxis);
   }
   else
   {
      status = DRMS_ERROR_INVALIDDATA;
   }

   return status;
}

/* Get the record's segment axis dimensions. */
int drms_segment_getdims(DRMS_Segment_t *seg, DRMS_SegmentDimInfo_t *di)
{
   int status = DRMS_SUCCESS;

   if (seg && di)
   {
      di->naxis = seg->info->naxis;
      memcpy(di->axis, seg->axis, sizeof(int) * di->naxis);
   }

   return status;
}

HContainer_t *drms_segment_createinfocon(DRMS_Env_t *drmsEnv,
					 const char *seriesName,
					 int *status)
{
     HContainer_t *ret = NULL;

     DRMS_Record_t *template = drms_template_record(drmsEnv, seriesName, status);

     if (*status == DRMS_SUCCESS)
     {
	  int size = hcon_size(&(template->segments));
	  if (size > 0)
	  {
	       char **nameArr = (char **)malloc(sizeof(char *) * size);
	       DRMS_SegmentInfo_t **valArr =
		 (DRMS_SegmentInfo_t **)malloc(sizeof(DRMS_SegmentInfo_t *) * size);

	       if (nameArr != NULL && valArr != NULL)
	       {
		    HIterator_t hit;
		    hiter_new_sort(&hit, &(template->segments), drms_segment_ranksort);
		    DRMS_Segment_t *seg = NULL;

		    int iSeg = 0;
		    while ((seg = hiter_getnext(&hit)) != NULL)
		    {
			 nameArr[iSeg] = seg->info->name;
			 valArr[iSeg] = seg->info;

			 iSeg++;
		    }

		    ret = hcon_create(sizeof(DRMS_SegmentInfo_t),
				      DRMS_MAXSEGNAMELEN,
				      NULL,
				      NULL,
				      (void **)valArr,
				      nameArr,
				      size);
	       }
	       else
	       {
		    *status = DRMS_ERROR_OUTOFMEMORY;
	       }

	       if (nameArr != NULL)
	       {
		    free(nameArr);
	       }

	       if (valArr != NULL)
	       {
		    free(valArr);
	       }
	  }
     }

     return ret;
}

void drms_segment_destroyinfocon(HContainer_t **info)
{
   hcon_destroy(info);
}

/* Return absolute path to segment file in filename.
   filename must be able the hold at least DRMS_MAXPATHLEN bytes. */
/* Must not assume that seg->record->su exists - if it doesn't
 * exist, attempt to fetch the SU from SUMS. If it still doesn't exist
 * then set the return filename to the empty string. */
void drms_segment_filename(DRMS_Segment_t *seg, char *filename)
{
   int statint;

   if (seg->info->protocol == DRMS_DSDS)
   {
      /* For the DSDS protocol, filename is not used, except to signify that
       * there is no data file.  In that case, it is set to the empty string. */
      if (strlen(seg->filename) > 0)
      {
         snprintf(filename, DRMS_MAXPATHLEN, "%s", seg->filename);
      }
      else if (filename)
      {
         *filename = '\0';
      }
   }
   else if (seg->info->protocol != DRMS_LOCAL)
   {
      /* Make sure the segment's SU was fetched from SUMS (there may be no such SU too). */
      DRMS_Record_t *rec = seg->record;

      statint = DRMS_SUCCESS;

      if (rec->sunum != -1LL && rec->su == NULL)
      {
         /* The storage unit has not been requested from SUMS yet. Do it. */
         if ((rec->su = drms_getunit(rec->env,
                                     rec->seriesinfo->seriesname,
                                     rec->sunum,
                                     1,
                                     &statint)) == NULL)
         {
            statint = DRMS_ERROR_NOSTORAGEUNIT;
            *(seg->filename) = '\0';
            *filename = '\0';
         }
         else
         {
            rec->su->refcount++;
         }
      }

      if (statint == DRMS_SUCCESS)
      {
         if (strlen(seg->filename)) {
            if (seg->info->protocol == DRMS_TAS)
              CHECKSNPRINTF(snprintf(filename, DRMS_MAXPATHLEN, "%s/%s",
                                     rec->su->sudir, seg->filename), DRMS_MAXPATHLEN);
            else
              CHECKSNPRINTF(snprintf(filename, DRMS_MAXPATHLEN, "%s/" DRMS_SLOTDIR_FORMAT "/%s",
                                     rec->su->sudir, rec->slotnum, seg->filename), DRMS_MAXPATHLEN);
         } else {
            if (seg->info->protocol == DRMS_TAS)
            {
               CHECKSNPRINTF(snprintf(filename, DRMS_MAXPATHLEN, "%s/%s.tas",
                                      rec->su->sudir, seg->info->name), DRMS_MAXPATHLEN);
               /* set default base name */
               snprintf(seg->filename, sizeof(seg->filename), "%s.tas", seg->info->name);
            }
            else
            {
               CHECKSNPRINTF(snprintf(filename, DRMS_MAXPATHLEN, "%s/" DRMS_SLOTDIR_FORMAT "/%s%s",
                                      rec->su->sudir, rec->slotnum, seg->info->name,
                                      drms_prot2ext(seg->info->protocol)), DRMS_MAXPATHLEN);
               /* set default base name */
               snprintf(seg->filename, sizeof(seg->filename), "%s%s", seg->info->name, drms_prot2ext(seg->info->protocol));
            }
         }
      }
   }
   /* for DRMS_LOCAL, filename is already set */
}

/* Delete the file storing the data of a segment. */
int drms_delete_segmentfile (DRMS_Segment_t *seg) {
  char filename[DRMS_MAXPATHLEN];

  drms_segment_filename (seg, filename);
  if (unlink (filename)) {
    perror ("ERROR in drms_delete_segmentfile: unlink failed with");
    return DRMS_ERROR_UNLINKFAILED;
  } else return DRMS_SUCCESS;
}

/*  Wrapper for __drms_segment_lookup without the recursion depth counter  */
DRMS_Segment_t *drms_segment_lookup (DRMS_Record_t *rec, const char *segname) {
  DRMS_Segment_t *seg = __drms_segment_lookup (rec, segname, 0);

  if (!seg) return NULL;
  if (seg->info->scope == DRMS_CONSTANT) {

    // If the recnum of the record where the constant segment is stored
    // has not yet been set, return the current segment (for writing
    // purpose), otherwise return the constant segment.
    if (!seg->info->cseg_recnum) {
      return seg;
    } else {
      if (seg->record->recnum == seg->info->cseg_recnum) {
	return seg;
      } else {
	int status = 0;
	DRMS_Record_t *rec2 = drms_retrieve_record(rec->env, rec->seriesinfo->seriesname, seg->info->cseg_recnum, NULL, &status);
	if (status) {
	  fprintf(stderr, "Failed to retrieve record for constant segment, recnum = %lld", seg->info->cseg_recnum);
	  return NULL;
	}
	return drms_segment_lookup(rec2, segname);
      }
    }
  } else return seg;
}

/* Because elements of an hcontainer are unordered, we need to use the segnum field
 * to sort the elements. This is achieved by using the drms_segment_ranksort()
 * comparator. Then we have to do a linear search for the element with the
 * desired segnum. */
DRMS_Segment_t *drms_segment_lookupnum(DRMS_Record_t *rec, int segnum)
{
   HIterator_t hit;
   DRMS_Segment_t *seg = NULL;

   hiter_new_sort(&hit, &rec->segments, drms_segment_ranksort);
   while ((seg = (DRMS_Segment_t *)hiter_getnext(&hit)) != NULL)
   {
      if (seg->info->segnum == segnum)
      {
         break;
      }
      else if (seg->info->segnum > segnum)
      {
         seg = NULL;
         break;
      }
   }

   if (seg)
   {
      /* found matching segment */

      // This is to properly handle link segment and constant segment.
      seg = drms_segment_lookup(rec, seg->info->name);
   }

   hiter_free(&hit);

   return seg;
}

DRMS_Segment_t *drms_segment_lookupindex(DRMS_Record_t *rec, int index, int followLink)
{
    HIterator_t hit;
    DRMS_Segment_t *seg = NULL;
    int count;

    if (rec == NULL)
    {
        return NULL;
    }

    if (index < 0 || index > drms_record_numsegments(rec) - 1)
    {
        return NULL;
    }

    hiter_new_sort(&hit, &rec->segments, drms_segment_ranksort);
    for (count = 0; count <= index; count++)
    {
        seg = (DRMS_Segment_t *)hiter_getnext(&hit);
        if (!seg)
        {
            /* This shouldn't happen since index < drms_record_numsegments(rec). */
            break;
        }
    }

    if (seg && followLink)
    {
      /* found matching segment */

      // This is to properly handle link segment and constant segment.
      seg = drms_segment_lookup(rec, seg->info->name);
    }

    hiter_free(&hit);

    return seg;
}


#if 0
/* I was mistaken. See comment in drms_link_follow(). */

/* When a linked segment is accessed (drms_segment_lookup() and drms_segment_lookupnum), the linked record
 * containing that segment is retrieved from the db. If the record is already in the cache, then instead
 * of retrieving the record information from the db, the refcount on this record is incremented. The
 * record must then be freed, otherwise memory will be leaked. If the refcount > 1, then no memory
 * will be released during this call, but if for every access drms_segment_destroy() is also called,
 * then the memory allocated to the linked record will be freed.
 *
 * Unfortunately, DRMS_Segment_t does not have any information to indicate if the segment is a linked segment.
 * If the caller provides a non-linked segment to this function, then this will possibly delete the
 * containing record, which would be bad. Given the current design, there is no good way to protect against this.
 * Have the caller provide the original segment too, and then verify that it links to the target segment.
 */
void drms_segment_destroy(DRMS_Segment_t *oSeg, DRMS_Segment_t **pSeg)
{
    DRMS_Segment_t *seg = NULL;
    DRMS_Link_t *link = NULL;
    char hashkey[DRMS_MAXHASHKEYLEN];
    void *lookup = NULL;
    DRMS_Record_t *linkedRec = NULL;

    if (oSeg && pSeg && (seg = *pSeg))
    {
        if (oSeg->record && oSeg->info->islink && *oSeg->info->linkname != '\0')
        {
            link = hcon_lookup_lower(&oSeg->record->links, oSeg->info->linkname);

            if (link)
            {
                if ((link->info->type == STATIC_LINK && link->recnum != -1) ||
                    (link->info->type == DYNAMIC_LINK && link->isset))
                {
                    /* The link is set. */
                    drms_make_hashkey(hashkey, link->info->target_series, link->recnum);
                    lookup = hcon_lookup_lower(mapRec, hashkey);
                    if (lookup)
                    {

                        linkedRec = *((DRMS_Record_t **)lookup);

                        /* drms_free_record() will decrement the record's refcount, and if this results
                         * in a refcount of 0, then the record is removed from the record cache. When this
                         * happens, the segment (seg) gets freed, without freeing seg->seriesinfo.
                         * Do NOT free seg->seriesinfo. Freeing the containing record in the series cache
                         * will free the info struct.
                         */
                        if (linkedRec == seg->record)
                        {
                            drms_free_record(seg->record);
                            seg->record = NULL;

                            *pSeg = NULL;
                        }
                    }
                }
            }
        }
    }
}
#endif

/*************************** Segment Data functions **********************/

FILE *drms_segment_fopen(DRMS_Segment_t *seg, const char *newfilename, int append, int *status)
{
   FILE *file = NULL;
   DRMS_Record_t *rec = NULL;
   int statint = DRMS_SUCCESS;
   char filename[DRMS_MAXPATHLEN];
   char path[DRMS_MAXPATHLEN];

   if (seg)
   {
      rec = seg->record;

      /* First, bring data file online (if it isn't online) */
      if (rec->sunum != -1LL && rec->su == NULL)
      {
         /* The storage unit has not been requested from SUMS yet. Do it. */
         if ((rec->su = drms_getunit(rec->env,
                                     rec->seriesinfo->seriesname,
                                     rec->sunum,
                                     1,
                                     &statint)) == NULL)
         {
            statint = DRMS_ERROR_NOSTORAGEUNIT;
         }
         else
         {
            rec->su->refcount++;
         }
      }

      if (!statint)
      {
         /* If the file is being created (the storage unit is DRMS_READWRITE and the
          * file doesn't already exist), then you need to set seg->filename.
          * drms_segment_filename() yields the default file name to create if
          * it doesn't exist already. Override that with newfilename if the
          * caller desires. */
         struct stat stbuf;

         drms_segment_filename(seg, path);

         if (rec->su->mode == DRMS_READWRITE && stat(path, &stbuf))
         {
            char *tmp = strdup(path);
            char *pc = strrchr(tmp, '/');
            *pc = '\0';
            pc++;

            if (newfilename)
            {
               snprintf(filename, sizeof(filename), "%s", newfilename);
               snprintf(path, sizeof(path), "%s/%s", tmp, newfilename);
            }
            else
            {
               /* extract filename from path */
               snprintf(filename, sizeof(filename), "%s", pc);
            }

            CHECKSNPRINTF(snprintf(seg->filename, DRMS_MAXSEGFILENAME, "%s", filename),
                          DRMS_MAXSEGFILENAME);

            free(tmp);
         }

         /* If the segment is part of a record that can be written to, then rec->su->mode == DRMS_READWRITE.
          * If the segment is part of a recrd that cannot be written to, then rec->su->mode == DRMS_READONLY.
          * So, no need to have a parameter that allows the caller to specify the mode. */
         if (rec->su->mode == DRMS_READONLY)
         {
            file = fopen(path, "r");
         }
         else if (rec->su->mode == DRMS_READWRITE)
         {
            if (append)
            {
               file = fopen(path, "a+");
            }
            else
            {
               file = fopen(path, "w+");
            }
         }
         else
         {
            statint = DRMS_ERROR_INVALIDSU;
         }

         if (!statint && !file)
         {
            statint = DRMS_ERROR_INVALIDFILE;
         }
      }
   }

   if (status)
   {
      *status = statint;
   }

   return file;
}

int drms_segment_fclose(FILE *fptr)
{
   int ret = 0;

   if (fptr)
   {
      ret = fclose(fptr);
      if (ret)
      {
         ret = DRMS_ERROR_IOERROR;
      }
   }

   return ret;
}

/* Open an array data segment.

   a) If the corresponding data file exists, read the
   entire data array into memory. Convert it to the type given as
   argument. If type=DRMS_TYPE_RAW then  the data is
   read into an array of the same type it is stored as on disk.
   b) If the data file does not exist, then return a data array filed with
   the MISSING value for the given type.

   The read functions do not apply bscale or bzero.  This conversion is
   performed at the end of the function (via drms_array_convert_inplace()).
*/


DRMS_Array_t *drms_segment_read(DRMS_Segment_t *seg, DRMS_Type_t type,
				int *status)
{
    int statint=0,i;
    DRMS_Array_t *arr = NULL;
    char filename[DRMS_MAXPATHLEN];
    DRMS_Record_t *rec;

    CHECKNULL_STAT(seg,status);

    rec = seg->record;

    if (seg->info->scope == DRMS_CONSTANT &&
        !seg->info->cseg_recnum) {
        fprintf(stderr, "ERROR in drms_segment_read: constant segment has not yet"
                " been initialized. Series = %s.\n",  rec->seriesinfo->seriesname);
        statint = DRMS_ERROR_INVALIDACTION;
        goto bailout1;
    }

    if (seg->info->protocol == DRMS_GENERIC)
    {
        fprintf(stderr, "ERROR in drms_segment_read: Not appropriate function"
                "for DRMS_GENERIC segment.  Series = %s.\n",  rec->seriesinfo->seriesname);
        statint = DRMS_ERROR_INVALIDACTION;
        goto bailout1;
    }

    if (rec->sunum != -1LL && rec->su==NULL)
    {
        /* The storage unit has not been requested from SUMS yet. Do it. */
        if ((rec->su = drms_getunit(rec->env, rec->seriesinfo->seriesname,
                                    rec->sunum, 1, &statint)) == NULL)
        {
            /* A record may have an SUNUM, but the corresponding SU may no longer exist. The
             * series may have archive == 0 so that the SU got removed by sum_rm. Attempting to
             * read a data-segment file from a record whose SU has been deleted is an
             * error, although the caller of drms_segment_read() won't typically be aware of this
             * situation, unless they called SUM_info() before calling drms_segment_read().
             * Return an error code that the call must deal with. */
            statint = DRMS_ERROR_NOSTORAGEUNIT;
            goto bailout1;
        }
        rec->su->refcount++;
    }

    drms_segment_filename(seg, filename);
#ifdef DEBUG
    printf("Trying to open segment file '%s'.\n",filename);
#endif

    if (seg->info->protocol == DRMS_DSDS || seg->info->protocol == DRMS_LOCAL)
    {
        /* For both of these protocols, the fits file was read with DSDS code. Be careful -
         * DSDS code does some unexpected things when reading fits files, like converting
         * all integer data to floating-point data. */
        char *dsdsParams;
        int ds;
        int rn;
        char *locfilename;

        if (seg->info->protocol == DRMS_DSDS)
        {
            if (!*filename)
            {
                /* This DSDS record has no data file. We don't actually use the
                 * filename here - the DSDS parameters are used below to fetch
                 * the file.  The filename is used to respond to requests for
                 * the segment filename. */
                fprintf(stderr, "There is no data file for this DSDS data record.\n");
                goto bailout1;
            }

            /* When the DSDS records were opened, a string representation of the keylist needed by
               to call vds_open() is saved in the record's seriesinfo description field. */
            dsdsParams = (char *)malloc(sizeof(char) * kDSDS_MaxHandle);
            if (DSDS_GetDSDSParams(seg->record->seriesinfo, dsdsParams))
            {
                fprintf(stderr, "Couldn't get DSDS keylist.\n");
                goto bailout1;
            }

            ds = drms_getkey_int(seg->record, kDSDS_DS, &statint);
            rn = drms_getkey_int(seg->record, kDSDS_RN, &statint);

            locfilename = NULL;
        }
        else
        {
            dsdsParams = NULL;
            ds = -1;
            rn = -1;
            locfilename = strdup(seg->filename);
        }

        /* The DSDS and LOCAL protocols do not use SUMS.  Call into libdsds (if available)
         * to obtain data. */
        static void *hDSDS = NULL;
        static int attempted = 0;

        if (!attempted && !hDSDS)
        {
            kDSDS_Stat_t dsdsstat;
            hDSDS = DSDS_GetLibHandle(kLIBDSDS, &dsdsstat);
            if (dsdsstat != kDSDS_Stat_Success)
            {
                statint = DRMS_ERROR_CANTOPENLIBRARY;
            }

            attempted = 1;
        }

        if (hDSDS)
        {
            kDSDS_Stat_t dsdsStat;
            pDSDSFn_DSDS_segment_read_t pFn_DSDS_segment_read =
            (pDSDSFn_DSDS_segment_read_t)DSDS_GetFPtr(hDSDS, kDSDS_DSDS_SEGMENT_READ);
            pDSDSFn_DSDS_free_array_t pFn_DSDS_free_array =
            (pDSDSFn_DSDS_free_array_t)DSDS_GetFPtr(hDSDS, kDSDS_DSDS_FREE_ARRAY);

            if (pFn_DSDS_segment_read && pFn_DSDS_free_array)
            {
                DRMS_Array_t *copy = NULL;

                if (statint == DRMS_SUCCESS)
                {
                    arr = (*pFn_DSDS_segment_read)(dsdsParams, ds, rn, locfilename, &dsdsStat);
                }
                else
                {
                    goto bailout1;
                }

                if (dsdsStat == kDSDS_Stat_Success)
                {
                    /* Copy - the DSDS array should be freed by libdsds. */
                    long long datalen = drms_array_size(arr);
                    void *data = calloc(1, datalen);
                    if (data)
                    {
                        memcpy(data, arr->data, datalen);
                        copy = drms_array_create(arr->type, arr->naxis, arr->axis, data, &statint);
                        if (statint != DRMS_SUCCESS)
                        {
                            if (data)
                            {
                                free(data);
                            }
                            goto bailout;
                        }
                    }
                    else
                    {
                        statint = DRMS_ERROR_OUTOFMEMORY;
                        goto bailout;
                    }

                    copy->bzero = arr->bzero;
                    copy->bscale = arr->bscale;
                    copy->israw = arr->israw;

                    (*pFn_DSDS_free_array)(&arr);
                    arr = copy;

                    /* drms_open_records() makes a temporary series to contain all DSDS data
                     * ingested during a module session. It makes a single segment whose
                     * data type is determined by the bitpix value of the header of the first fits file
                     * in the set of fits files being accessed. To do this, it calls VDS_select_hdr()
                     * which does NOT convert integer data types to a floating-point data type.
                     * But the later call to drms_segment_read(), which calls sds_read_fits(), will
                     * convert all integer image data to either a double (if the actual type is
                     * int or long long) or a float (if the actual type is char or short), provided there
                     * are bzero/bscale keywords in the fits-file header. To cope with this
                     * discrepancy, DSDS_open_records(), which is called by drms_open_records(),
                     * creates a DRMS segment with the appropriate floating-point data type.
                     * All is good, so long as sds_read_fits() converts all integer
                     * images to floating-point images. But we found a bug in DSDS. If bzero/bscale
                     * values are missing, which implies a bzero of 0 and a bscale of 1, then
                     * sds_read_fits() will NOT convert the image data. If the data array
                     * were left untouched at this point, arr->type would be an integer type, but
                     * seg->info->type would be a floating-point type, and a mismatch error, detected
                     * near the end of drms_segment_read(), would be encountered.
                     *
                     * To work around this DSDS issue, at this point we convert the integer data to a
                     * floating-point data type. DSDS is always supposed to convert integer image
                     * data to floating-point data, so explicitly doing that here will patch
                     * the bug in DSDS.
                     */
                    if (copy->type == DRMS_TYPE_INT || copy->type == DRMS_TYPE_LONGLONG)
                    {
                        drms_array_convert_inplace(DRMS_TYPE_DOUBLE, arr->bzero, arr->bscale, arr);
                    }
                    else if (copy->type == DRMS_TYPE_CHAR || copy->type == DRMS_TYPE_SHORT)
                    {
                        drms_array_convert_inplace(DRMS_TYPE_FLOAT, arr->bzero, arr->bscale, arr);
                    }
                }
                else
                {
                    statint = DRMS_ERROR_LIBDSDS;
                    fprintf(stderr, "Error reading DSDS segment.\n");
                    goto bailout1;
                }
            }
            else
            {
                statint = DRMS_ERROR_LIBDSDS;
                goto bailout1;
            }
        }
        else
        {
            fprintf(stdout, "Your JSOC environment does not support DSDS database access.\n");
            statint = DRMS_ERROR_NODSDSSUPPORT;
        }

        if (dsdsParams)
        {
            free(dsdsParams);
        }

        if (locfilename)
        {
            free(locfilename);
        }

    } /* protocols DRMS_DSDS || DRMS_LOCAL */
    else
    {
        /* For the remaining protocols, the code needs to open the file. Under some circumstances, the
         * file could be missing. There could be multiple data segments, but not all data segments
         * have files in the storage unit directory (only some were written). This is not an error.
         * Unfortunately, the current design doesn't distinguish this sitation from the error
         * where the file is missing for some other reason (eg., DRMS crashes and fails to write
         * a file). So, we have to assume that there is no error. But how do we tell the user
         * that the file is missing since we have this requirement that the status cannot
         * return status? If status is not zero, this means "error". So, if a file is missing,
         * we have to assume an error. Compromise: don't write an error message, but issue an
         * error. */
        struct stat stbuf;

        if (stat(filename, &stbuf))
        {
            /* file filename is missing */
            statint = DRMS_ERROR_INVALIDFILE;
            goto bailout1;
        }

        switch(seg->info->protocol)
        {
            case DRMS_GENERIC:
            case DRMS_MSI:
            statint = DRMS_ERROR_NOTIMPLEMENTED;
            goto bailout1;
            break;
            case DRMS_BINARY:
            arr = malloc(sizeof(DRMS_Array_t));
            XASSERT(arr);
            if ((statint = drms_binfile_read(filename, 0, arr)))
            {
                fprintf(stderr,"Couldn't read segment from file '%s'.\n",
                        filename);
                goto bailout1;
            }
            break;
            case DRMS_BINZIP:
            arr = malloc(sizeof(DRMS_Array_t));
            XASSERT(arr);
            if ((statint = drms_zipfile_read(filename, 0, arr)))
            {
                fprintf(stderr,"Couldn't read segment from file '%s'.\n",
                        filename);
                goto bailout1;
            }
            break;
            case DRMS_FITZ:
            case DRMS_FITS:
            {
                CFITSIO_IMAGE_INFO *info = NULL;
                void *image = NULL;

                /* Call Tim's function to read data */
                if (fitsrw_readintfile(rec->env->verbose, filename, &info, &image, NULL) == CFITSIO_SUCCESS)
                {
                    if (drms_fitsrw_CreateDRMSArray(info, image, &arr))
                    {
                        fprintf(stderr,"Couldn't read segment from file '%s'.\n", filename);
                        goto bailout1;
                    }

                    /* Don't free image - arr has stolen it. */
                    cfitsio_free_these(&info, NULL, NULL);
                }
                else
                {
                    /* filename exists, but for some reason, cfitsio failed to read it. */
                    fprintf(stderr,"Couldn't read FITS file '%s'.\n", filename);
                    statint = DRMS_ERROR_FITSRW;
                    goto bailout1;
                }
            }
            break;
            case DRMS_FITZDEPRECATED:
            case DRMS_FITSDEPRECATED:
            {
                arr = NULL;
                statint = DRMS_ERROR_NOTIMPLEMENTED;
                fprintf(stderr,"Protocol DRMS_FITSDEPRECATED and DRMS_FITZDEPRECATED have been deprecated.\n");
                goto bailout1;
            }
            break;
            case DRMS_TAS:
            {
                /* Read the slice in the TAS file corresponding to this record's
                 slot. */

                /* The underlying fits file will have bzero/bscale fits keywords -
                 * those are used to populate arr. They must match the values
                 * that originate in the record's _bzero/_bscale keywords. They cannot
                 * vary across records. */
                if ((statint = drms_fitstas_readslice(seg->record->env,
                                                      filename,
                                                      seg->info->naxis,
                                                      seg->axis,
                                                      NULL,
                                                      NULL,
                                                      seg->record->slotnum,
                                                      &arr)) != DRMS_SUCCESS)
                {
                    fprintf(stderr,"Couldn't read segment from file '%s'.\n",
                            filename);
                    goto bailout1;
                }
            }
            break;
            default:
            statint = DRMS_ERROR_UNKNOWNPROTOCOL;
            goto bailout1;
        }
    }

    /* Check that dimensions match template. */
    if (arr->type != seg->info->type) {
        fprintf (stderr, "Data types in file (%d) do not match those in segment "
                 "descriptor (%d).\n", (int)arr->type, (int)seg->info->type);
        statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
        goto bailout;
    }
    if (arr->naxis != seg->info->naxis) {
        fprintf (stderr, "Number of axis in file (%d) do not match those in "
                 "segment descriptor (%d).\n", arr->naxis, seg->info->naxis);
        statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
        goto bailout;
    }

    if (seg->info->scope != DRMS_VARDIM)
    {
        for (i=0;i<arr->naxis;i++) {
            if (arr->axis[i] != seg->axis[i]) {
                fprintf (stderr,"Dimension of axis %d in file (%d) do not match those"
                         " in segment descriptor (%d).\n", i, arr->axis[i], seg->axis[i]);
                statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
                goto bailout;
            }
        }
    }

    for (i=0;i<arr->naxis;i++)
    arr->start[i] = 0;

    /* Set information about mapping from parent segment to array. */
    arr->parent_segment = seg;

    /* Scale and convert to desired type. */
    if (type == DRMS_TYPE_RAW)
    {
        arr->israw = 1;
    }
    else if (arr->type != type || arr->bscale != 1.0 || arr->bzero != 0.0)
    {
        /* convert TAS as well. */
        drms_array_convert_inplace(type, arr->bzero, arr->bscale, arr);
#ifdef DEBUG
        printf("converted with bzero=%g, bscale=%g\n",arr->bzero, arr->bscale);
#endif
        arr->israw = 0;
    }

    if (status)
    *status = DRMS_SUCCESS;

    return arr;

bailout:
    free(arr->data);
    free(arr);
bailout1:
#ifdef DEBUG
    printf("Segment = \n");
    drms_segment_print(seg);
#endif
    if (status)
    *status = statint;
    return NULL;
}


/* The dimensionality of start, end, and seg must all match.
 *
 */
DRMS_Array_t *drms_segment_readslice(DRMS_Segment_t *seg, DRMS_Type_t type,
				     axislen_t *start, axislen_t *end, int *status)
{
  int statint = 0, i;
  DRMS_Array_t *arr, *tmp;
  char filename[DRMS_MAXPATHLEN];
  DRMS_Record_t *rec;

  CHECKNULL_STAT(seg,status);

  rec = seg->record;
  if (rec->sunum != -1LL && rec->su==NULL)
  {
    /* The storage unit has not been requested from SUMS yet. Do it. */
    if ((rec->su = drms_getunit(rec->env, rec->seriesinfo->seriesname,
				rec->sunum, 1, &statint)) == NULL)
    {
       /* A record may have an SUNUM, but the corresponding SU may no longer exist. The
        * series may have archive == 0 so that the SU got removed by sum_rm. Attempting to
        * read a data-segment file from a record whose SU has been deleted is an
        * error, although the caller of drms_segment_readslice() won't typically be aware of this
        * situation, unless they called SUM_info() before calling drms_segment_readslice().
        * Return an error code that the call must deal with. */
       statint = DRMS_ERROR_NOSTORAGEUNIT;
       goto bailout1;
    }
    rec->su->refcount++;
  }

  drms_segment_filename(seg, filename);

  /* For all the protocols, the code needs to open the file. Under some circumstances, the
   * file could be missing. There could be multiple data segments, but not all data segments
   * have files in the storage unit directory (only some were written). This is not an error.
   * Unfortunately, the current design doesn't distinguish this sitation from the error
   * where the file is missing for some other reason (eg., DRMS crashes and fails to write
   * a file). So, we have to assume that there is no error. But how do we tell the user
   * that the file is missing since we have this requirement that the status cannot
   * return status? If status is not zero, this means "error". So, if a file is missing,
   * we have to assume an error. Compromise: don't write an error message, but issue an
   * error. */
  struct stat stbuf;

  if (stat(filename, &stbuf))
  {
     /* file filename is missing */
     statint = DRMS_ERROR_INVALIDFILE;
     goto bailout1;
  }

  /* For FITS, FITSZ, and TAS (which are implemented at the lowest level with a FITS file),
   * just read part of the file. cfitsio can read subsets of a file.
   * The other protocols read the whole file, then strip away what is needed,
   * which is inefficient.
   */
  if (seg->info->protocol == DRMS_FITS ||
      seg->info->protocol == DRMS_FITZ)
  {
     /* The underlying fits file will have bzero/bscale fits keywords -
      * those are used to populate arr. They must match the values
      * that originate in the record's _bzero/_bscale keywords. They cannot
      * vary across records. */
     if ((statint = drms_fitsrw_readslice(rec->env,
                                          filename,
                                          seg->info->naxis,
                                          start,
                                          end,
                                          &arr)) != DRMS_SUCCESS)
     {
        fprintf(stderr,"Couldn't read slice from file '%s'.\n", filename);
        goto bailout1;
     }
  }
  else if (seg->info->protocol == DRMS_TAS)
  {
     if ((statint = drms_fitstas_readslice(rec->env,
                                           filename,
                                           seg->info->naxis,
                                           seg->axis,
                                           start,
                                           end,
                                           seg->record->slotnum,
                                           &arr)) != DRMS_SUCCESS)
     {
        fprintf(stderr,"Couldn't read slice from file '%s'.\n", filename);
        goto bailout1;
     }
  }
  else
  {
     switch(seg->info->protocol)
     {
        case DRMS_BINARY:
          arr = malloc(sizeof(DRMS_Array_t));
          XASSERT(arr);
          if ((statint = drms_binfile_read(filename, 0, arr)))
          {
             fprintf(stderr,"Couldn't read segment from file '%s'.\n",
                     filename);
             goto bailout1;
          }
          break;
        case DRMS_BINZIP:
          arr = malloc(sizeof(DRMS_Array_t));
          XASSERT(arr);
          if ((statint = drms_zipfile_read(filename, 0, arr)))
          {
             fprintf(stderr,"Couldn't read segment from file '%s'.\n",
                     filename);
             goto bailout1;
          }
          break;
        case DRMS_GENERIC:
          *status = DRMS_ERROR_INVALIDACTION;
          return NULL;
          break;
        case DRMS_MSI:
          *status = DRMS_ERROR_NOTIMPLEMENTED;
          return NULL;
          break;
        case DRMS_FITZDEPRECATED:
        case DRMS_FITSDEPRECATED:
          {
             arr = NULL;
             statint = DRMS_ERROR_NOTIMPLEMENTED;
             fprintf(stderr,"Protocols DRMS_FITSDEPRECATED and DRMS_FITZDEPRECATED have been deprecated.\n");
             goto bailout1;
          }
          break;
        default:
          if (status)
            *status = DRMS_ERROR_UNKNOWNPROTOCOL;
          return NULL;
     }

     /* Cut out the desired part of the array. */
     if ((tmp = drms_array_slice(start,end,arr)) == NULL)
       drms_free_array(arr);
     arr = tmp;
     if (!arr)
       goto bailout1;
  }

  /* Check that dimensions match template. */
  if (arr->type != seg->info->type) {
     fprintf (stderr, "Data types in file (%d) do not match those in segment "
              "descriptor (%d).\n", (int)arr->type, (int)seg->info->type);
     statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
     goto bailout;
  }
  if (arr->naxis != seg->info->naxis) {
     fprintf (stderr, "Number of axis in file (%d) do not match those in "
              "segment descriptor (%d).\n", arr->naxis, seg->info->naxis);
     statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
     goto bailout;
  }

  if (seg->info->scope != DRMS_VARDIM)
  {
     for (i=0;i<arr->naxis;i++) {
        if (arr->axis[i] > seg->axis[i]) {
           fprintf (stderr,"Dimension of axis %d in file (%d) is incompatible with those"
                    " in segment descriptor (%d).\n", i, arr->axis[i], seg->axis[i]);
           statint = DRMS_ERROR_SEGMENT_DATA_MISMATCH;
           goto bailout;
        }
     }
  }

  for (i=0;i<arr->naxis;i++)
    arr->start[i] = 0;

  /* Set information about mapping from parent segment to array. */
  arr->parent_segment = seg;

  /* Scale and convert to desired type. */
  if (type == DRMS_TYPE_RAW)
  {
     arr->israw = 1;
  }
  else if (arr->type != type || arr->bscale != 1.0 || arr->bzero != 0.0)
  {
     /* convert TAS as well. */
     drms_array_convert_inplace(type, arr->bzero, arr->bscale, arr);
#ifdef DEBUG
     printf("converted with bzero=%g, bscale=%g\n",arr->bzero, arr->bscale);
#endif
     arr->israw = 0;
  }

  if (status)
    *status = DRMS_SUCCESS;

  return arr;

 bailout:
  drms_free_array(arr);
 bailout1:
  if (status)
    *status = statint;
  return NULL;
}

/* functions shared by drms_segment_write() and drms_segment_writeslice() */
static DRMS_Array_t *ScaleOutputArray(DRMS_Segment_t *seg, DRMS_Array_t *arr, int autoscale)
{
   double autobscale, autobzero;
   double bscale, bzero; /* These are actually inverses used to convert arr->data, so that the resulting
                          * values must be interpreted with arr->bzero and arr->bscale */

   /* Can autoscale only if output file type is an int. */
   if (autoscale)
     drms_segment_autoscale(seg, arr, &autobzero, &autobscale);

   int outisraw = 0;
   int copyarrscale = 0;

   DRMS_Array_t *out = NULL;

   /* bzero and bscale will be applied before data are written. */

   if (arr->type != DRMS_TYPE_FLOAT && arr->type != DRMS_TYPE_DOUBLE)
   {
      /* bzero/bscale are not relevant when the data type is not
       * an integer type; so israw is also not relevant */
      if (arr->israw)
      {
         /* means integer data are in 'scaled' units, not physical units. */
         if (seg->info->type == DRMS_TYPE_FLOAT || seg->info->type == DRMS_TYPE_DOUBLE)
         {
            /* array is RAW integer, file is float - scale */
            bzero = arr->bzero;
            bscale = arr->bscale;

            copyarrscale = 0;
            outisraw = 0;
         }
         else
         {
            /* array is RAW integer, file is integer */
            /* No scaling should occur.  Copy bzero/bscale from arr to FITS file. */
            if (!autoscale)
            {
               bzero = 0.0;
               bscale = 1.0;
            }
            else
            {
               if (arr->bzero != autobzero || arr->bscale != autobscale)
               {
                  bzero = (arr->bzero - autobzero) / autobscale;
                  bscale = (arr->bscale) / autobscale;
               }
               else
               {
                  bzero = 0.0;
                  bscale = 1.0;
               }
            }

            copyarrscale = 1;
            outisraw = 1;
         }
      }
      else
      {
         /* No scaling should occur - these are integers in physical units */
         if (!autoscale)
         {
            bzero = 0.0;
            bscale = 1.0;
         }
         else if (autobzero != 0.0 || autobscale != 1.0)
         {
            bzero = -autobzero / autobscale;
            bscale = 1.0 / autobscale;
         }

         copyarrscale = 0;
         outisraw = 0;
      }
   }
   else
   {
      /* float array */
      if (seg->info->type != DRMS_TYPE_FLOAT && seg->info->type != DRMS_TYPE_DOUBLE)
      {
         /* float array, integer file - scale */
         if (!autoscale)
         {
            bzero = -arr->bzero / arr->bscale;
            bscale = 1.0 / arr->bscale;
         }
         else
         {
            bzero = -autobzero / autobscale;
            bscale = 1.0 / autobscale;
         }

         copyarrscale = 1;
         outisraw = 1;
      }
      else
      {
         /* array is float, file is float - no scaling */
         bzero = 0.0;
         bscale = 1.0;
         copyarrscale = 0;
         outisraw = 0;
      }
   }

#ifdef DEBUG
   printf("in write_segment:  bzero=%g, bscale = %g\n",bzero,bscale);
#endif

   /* Convert to desired type. */
   if( arr->type != seg->info->type || fabs(bzero)!=0.0 || bscale!=1.0)
   {
      out = drms_array_convert(seg->info->type, bzero, bscale, arr);
   }
   else
   {
      out = arr;
   }

   if (copyarrscale)
   {
      out->bzero = arr->bzero;
      out->bscale = arr->bscale;
   }
   else
   {
      out->bzero = 0.0;
      out->bscale = 1.0;
   }
   out->israw = outisraw ? 1 : 0;

   return out;
}

DRMS_Array_t *drms_segment_scale_output_array(DRMS_Segment_t *segment, DRMS_Array_t *data_array)
{
		return ScaleOutputArray(segment, data_array, 0);
}

/* Write the array argument to the file occupied by the
   segment argument. The array dimension and type must match the
   segment dimension and type. */
static int drms_segment_writeinternal(DRMS_Segment_t *seg, DRMS_Array_t *arr, int autoscale, int wkeys)
{
  int status,i;
  char filename[DRMS_MAXPATHLEN];
  DRMS_Array_t *out;
  DRMS_SeriesVersion_t vers2_1 = {"2.1", ""};
  CFITSIO_KEYWORD *fitskeys = NULL;

  if (seg->info->scope == DRMS_CONSTANT &&
      seg->info->cseg_recnum) {
    fprintf(stderr, "ERROR in drms_segment_write: constant segment has already"
	    " been initialized. Series = %s.\n",  seg->record->seriesinfo->seriesname);
    return DRMS_ERROR_INVALIDACTION;
  }

  if (seg->info->protocol == DRMS_GENERIC)
    {
    fprintf(stderr, "ERROR in drms_segment_write: Not appropriate function"
       "for DRMS_GENERIC segment.  Series = %s.\n", seg->record->seriesinfo->seriesname);
    return(DRMS_ERROR_INVALIDACTION);
    }

  if (seg && arr)
  {
    if (seg->record->readonly)
    {
      fprintf(stderr,"Cannot write segment to read-only record.\n");
      return DRMS_ERROR_RECORDREADONLY;
    }
    if (arr->data == NULL)
    {
      fprintf(stderr,"Array contains no data!\n");
      return DRMS_ERROR_NULLPOINTER;
    }

    if (seg->info->scope != DRMS_VARDIM)
    {
       if (arr->naxis != seg->info->naxis)
       {
	  fprintf(stderr,"Number of axis in file (%d) do not match those in "
		  "segment descriptor (%d).\n",arr->naxis,seg->info->naxis);
	  return DRMS_ERROR_INVALIDDIMS;
       }
       for (i=0;i<arr->naxis;i++)
       {
	  if (arr->axis[i] != seg->axis[i])
	  {
	     fprintf(stderr,"Dimension of axis %d in file (%d) do not match those"
		     " in segment descriptor (%d).\n",i,arr->axis[i],
		     seg->axis[i]);
	     return DRMS_ERROR_INVALIDDIMS;
	  }
       }
    }
    else
    {
       /* Use the input array's axis dimensionality and lengths for the output file */
       seg->info->naxis = arr->naxis;

       for (i=0;i<arr->naxis;i++)
       {
	  seg->axis[i] = arr->axis[i];
       }
    }

    out = ScaleOutputArray(seg, arr, autoscale);

    drms_segment_filename(seg, filename);
    if (!strlen(seg->filename)) {
      strncpy(seg->filename, rindex(filename, '/')+1, DRMS_MAXSEGFILENAME-1);
    }

    char key[DRMS_MAXKEYNAMELEN];

    switch(seg->info->protocol)
    {
    case DRMS_BINARY:
      status = drms_binfile_write(filename, out);

      if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
      {
         if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
         {
            snprintf(key, sizeof(key), "%s_bzero", seg->info->name);
            drms_setkey_double(seg->record, key, out->bzero);
            snprintf(key, sizeof(key), "%s_bscale", seg->info->name);
            drms_setkey_double(seg->record, key, out->bscale);
         }
      }

      if (status)
	goto bailout;
      break;
    case DRMS_BINZIP:
      status = drms_zipfile_write(filename, out);

      if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
      {
         if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
         {
            snprintf(key, sizeof(key), "%s_bzero", seg->info->name);
            drms_setkey_double(seg->record, key, out->bzero);
            snprintf(key, sizeof(key), "%s_bscale", seg->info->name);
            drms_setkey_double(seg->record, key, out->bscale);
         }
      }

      if (status)
	goto bailout;
      break;
    case DRMS_FITZ:
      {
	 if (out->type == DRMS_TYPE_STRING)
	 {
	    fprintf(stderr, "Can't save string data into a fits file.\n");
            status = DRMS_ERROR_INVALIDTYPE;
	    goto bailout;
	 }

         /* If wkeys, then export DRMS keys to FITS keys*/
         if (wkeys)
         {
            fitskeys = fitsexport_mapkeys(NULL, seg, NULL, NULL, NULL, NULL, NULL, &status);
            if (status)
            {
               fprintf(stderr, "WARNING - failure to export one or more keywords.\n");
               status = DRMS_SUCCESS;
            }
         }

	 CFITSIO_IMAGE_INFO imginfo;

	 if (!drms_fitsrw_SetImageInfo(out, &imginfo))
	 {
         /* Need to change the compression parameter to something meaningful
          * (although new users should just use the DRMS_FITS protocol )*/
         if (fitsrw_writeintfile(seg->record->env->verbose, filename, &imginfo, out->data, seg->cparms, fitskeys) != CFITSIO_SUCCESS)
         {
             status = DRMS_ERROR_FITSRW;
             goto bailout;
         }

         /* imginfo will contain the correct bzero/bscale.  This may be different
          * that what lives in seg->bzero/bscale - those values can be overriden.
          * If they are overridden, then the new values must be saved in the
          * underlying keywords where they are stored. */
         if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
         {
             if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
             {
                 snprintf(key, sizeof(key), "%s_bzero", seg->info->name);
                 drms_setkey_double(seg->record, key, drms_fitsrw_GetBzeroFromInfo(&imginfo));
                 snprintf(key, sizeof(key), "%s_bscale", seg->info->name);
                 drms_setkey_double(seg->record, key, drms_fitsrw_GetBscaleFromInfo(&imginfo));
             }
         }
	 }
	 else
	 {
            status = DRMS_ERROR_SEGMENTWRITE;
	    goto bailout;
	 }

         if (fitskeys)
         {
            cfitsio_free_keys(&fitskeys);
         }
      }
      break;
    case DRMS_FITS:
      {
	 if (out->type == DRMS_TYPE_STRING)
	 {
	    fprintf(stderr, "Can't save string data into a fits file.\n");
            status = DRMS_ERROR_INVALIDTYPE;
	    goto bailout;
	 }

         /* If wkeys, then export DRMS keys to FITS keys*/
         if (wkeys)
         {
            fitskeys = fitsexport_mapkeys(NULL, seg, NULL, NULL, NULL, NULL, NULL, &status);
            if (status)
            {
               fprintf(stderr, "WARNING - failure to export one or more keywords.\n");
               status = DRMS_SUCCESS;
            }
         }

	 CFITSIO_IMAGE_INFO imginfo;

	 if (!drms_fitsrw_SetImageInfo(out, &imginfo))
	 {
	    if (fitsrw_writeintfile(seg->record->env->verbose, filename, &imginfo, out->data, seg->cparms, fitskeys) != CFITSIO_SUCCESS)
            {
               status = DRMS_ERROR_FITSRW;
               goto bailout;
            }

            /* imginfo will contain the correct bzero/bscale.  This may be different
             * that what lives in seg->bzero/bscale - those values can be overriden.
             * If they are overridden, then the new values must be saved in the
             * underlying keywords where they are stored. */
            if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
            {
               if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
               {
                   snprintf(key, sizeof(key), "%s_bzero", seg->info->name);
                   drms_setkey_double(seg->record, key, drms_fitsrw_GetBzeroFromInfo(&imginfo));
                   snprintf(key, sizeof(key), "%s_bscale", seg->info->name);
                   drms_setkey_double(seg->record, key, drms_fitsrw_GetBscaleFromInfo(&imginfo));
               }
            }
	 }
	 else
	 {
            status = DRMS_ERROR_SEGMENTWRITE;
	    goto bailout;
	 }

         if (fitskeys)
         {
            cfitsio_free_keys(&fitskeys);
         }
      }
      break;
    case DRMS_MSI:
      return DRMS_ERROR_NOTIMPLEMENTED;
      break;
    case DRMS_TAS:
      {
          char virgin[PATH_MAX];
          struct stat stBuf;

         /* seg->bzero and seg->bscale cannot be overridden - all records must
          * have the same bzero and bscale values, since they share the same
          * fits file */
         if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
         {
            if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
            {
               fprintf(stderr, "The output array's bzero/bscale values (%f, %f) do not match those of the TAS file (%f, %f).\n", out->bzero, out->bscale, seg->bzero, seg->bscale);
                status = DRMS_ERROR_INVALIDSCALING;
                goto bailout;
            }
         }

         status = drms_fitstas_writeslice(seg->record->env,
                                          seg,
                                          filename,
                                          seg->info->naxis,
                                          seg->axis,
                                          NULL,
                                          NULL,
                                          seg->record->slotnum,
                                          out);

         if (status)
           goto bailout;

          /* We successfully wrote a slice to a TAS file, so now we have to delete the corresponding .virgin file. This
           * will ensure that we do NOT delete the TAS file during module shutdown. */
          snprintf(virgin, sizeof(virgin), "%s.virgin", filename);
          if (!stat(virgin, &stBuf))
          {
              /* Virgin file exists, delete it. */
              unlink(virgin);
          }
      }
      break;
    case DRMS_FITZDEPRECATED:
      status = DRMS_ERROR_NOTIMPLEMENTED;
      fprintf(stderr,"Protocol DRMS_FITZDEPRECATED has been deprecated.\n");
      goto bailout;
      break;
    case DRMS_FITSDEPRECATED:
      status = DRMS_ERROR_NOTIMPLEMENTED;
      fprintf(stderr,"Protocol DRMS_FITSDEPRECATED has been deprecated.\n");
      goto bailout;
      break;
    default:
      return DRMS_ERROR_UNKNOWNPROTOCOL;
    }

    if (out!=arr)
      drms_free_array(out);

  if (seg->info->scope == DRMS_CONSTANT &&
      !seg->info->cseg_recnum) {
    if (seg->record->lifetime == DRMS_TRANSIENT) {
      fprintf(stderr, "Error: cannot set constant segment in a transient record\n");
      status = DRMS_ERROR_SEGMENTWRITE;
      goto bailout;
    }
    return drms_segment_set_const(seg);
  }

  return DRMS_SUCCESS;
  }
  else
    return DRMS_ERROR_NULLPOINTER;

 bailout:
  if (out && out!=arr)
    drms_free_array(out);

  if (fitskeys)
  {
     cfitsio_free_keys(&fitskeys);
  }

  fprintf(stderr,"ERROR: Couldn't write data to file '%s'.\n", filename);
  return status;
}

int drms_segment_write(DRMS_Segment_t *seg, DRMS_Array_t *arr, int autoscale)
{
   return drms_segment_writeinternal(seg, arr, autoscale, 0);
}

int drms_segment_writewithkeys(DRMS_Segment_t *seg, DRMS_Array_t *arr, int autoscale)
{
   return drms_segment_writeinternal(seg, arr, autoscale, 1);
}

int drms_segment_writeslice_ext(DRMS_Segment_t *seg,
                                DRMS_Array_t *arr,
                                axislen_t *start,
                                axislen_t *end,
                                int *finaldims,
                                int autoscale)
{
  int status,i;
  char filename[DRMS_MAXPATHLEN];
  DRMS_Array_t *out;
  DRMS_SeriesVersion_t vers2_1 = {"2.1", ""};

  if (seg->info->scope == DRMS_CONSTANT &&
      seg->info->cseg_recnum) {
     fprintf(stderr, "ERROR in drms_segment_write: constant segment has already"
             " been initialized. Series = %s.\n",  seg->record->seriesinfo->seriesname);
     return DRMS_ERROR_INVALIDACTION;
  }

  if (seg->info->protocol == DRMS_GENERIC)
  {
     fprintf(stderr, "ERROR in drms_segment_write: Not appropriate function"
             "for DRMS_GENERIC segment.  Series = %s.\n", seg->record->seriesinfo->seriesname);
     return(DRMS_ERROR_INVALIDACTION);
  }

  if (seg && arr)
  {
     if (seg->record->readonly)
     {
        fprintf(stderr,"Cannot write segment to read-only record.\n");
        return DRMS_ERROR_RECORDREADONLY;
     }
     if (arr->data == NULL)
     {
        fprintf(stderr,"Array contains no data!\n");
        return DRMS_ERROR_NULLPOINTER;
     }

     if (seg->info->scope != DRMS_VARDIM)
     {
        if (arr->naxis != seg->info->naxis)
        {
           fprintf(stderr,"Number of axis in file (%d) do not match those in "
                   "segment descriptor (%d).\n",arr->naxis,seg->info->naxis);
           return DRMS_ERROR_INVALIDDIMS;
        }
        for (i=0;i<arr->naxis;i++)
        {
           if (start[i] < 0 || end[i] > seg->axis[i] - 1)
           {
              fprintf(stderr,
                      "Axis slice '[%d, %d]' not entirely within data array boundaries.\n",
                      start[i], end[i]);
              return DRMS_ERROR_INVALIDDIMS;
           }

           if (end[i] - start[i] + 1 != arr->axis[i])
           {
              fprintf(stderr,
                      "Axis slice dimensions (%d) do not match data dimensions (%d).\n",
                      end[i] - start[i] + 1, arr->axis[i]);
              return DRMS_ERROR_INVALIDDIMS;
           }
        }
     }
     else
     {
        const char *riceID = "compress rice";
        size_t sizestr = 64;
        char *tilestr = malloc(sizestr);
        char strbuf[64];

        memset(tilestr, 0, sizestr);

        for (i=0;i<arr->naxis;i++)
        {
           if (i == 0)
           {
              snprintf(strbuf, sizeof(strbuf), "%d", arr->axis[i]);
              tilestr = base_strcatalloc(tilestr, strbuf, &sizestr);
           }
           else
           {
              snprintf(strbuf, sizeof(strbuf), ",%d", arr->axis[i]);
              tilestr = base_strcatalloc(tilestr, strbuf, &sizestr);
           }
        }

        /* if the jsd specifies "compress Rice" or "compress', then we should make the compression-tile size match
         * the output array's dimensions (for efficiency). */
        if (strcasestr(seg->cparms, "compress"))
        {
           snprintf(seg->cparms, sizeof(seg->cparms), "%s %s", riceID, tilestr);
        }

        free(tilestr);
     }

     out = ScaleOutputArray(seg, arr, autoscale);

     drms_segment_filename(seg, filename);
     if (!strlen(seg->filename)) {
        strncpy(seg->filename, rindex(filename, '/')+1, DRMS_MAXSEGFILENAME-1);
     }

     switch(seg->info->protocol)
     {
        case DRMS_GENERIC:
        case DRMS_BINARY:
        case DRMS_BINZIP:
        case DRMS_MSI:
        case DRMS_FITZDEPRECATED:
        case DRMS_FITSDEPRECATED:
          status = DRMS_ERROR_NOTIMPLEMENTED;
          fprintf(stderr,"Protocol DRMS_FITSDEPRECATED and DRMS_FITZDEPRECATED have been deprecated.\n");
          goto bailout;
          break;
        case DRMS_FITZ:
        case DRMS_FITS:
         {
             if (out->type == DRMS_TYPE_STRING)
             {
                 fprintf(stderr, "Can't save string data into a fits file.\n");
                 goto bailout;
             }

             /* When writing a slice, bzero/bscale must match the segment's bzero/bscale.
              * Otherwise, you could write slices with differing bzero/bscale values,
              * which would be a big problem. */
             if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
             {
                 if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
                 {
                     fprintf(stderr, "The output array's bzero/bscale values (%f, %f) do not match those of the FITS file (%f, %f).\n", out->bzero, out->bscale, seg->bzero, seg->bscale);
                     status = DRMS_ERROR_INVALIDSCALING;
                     goto bailout;
                 }
             }

             if ((status = drms_fitsrw_writeslice_ext(seg->record->env,
                                                      seg,
                                                      filename,
                                                      out->naxis,
                                                      start,
                                                      end,
                                                      finaldims,
                                                      out)) != DRMS_SUCCESS)
                 goto bailout;
         }
          break;
        case DRMS_TAS:
         {
             char virgin[PATH_MAX];
             struct stat stBuf;

             /* seg->bzero and seg->bscale cannot be overridden - all records must
              * have the same bzero and bscale values, since they share the same
              * fits file */
             if (drms_series_isvers(seg->record->seriesinfo, &vers2_1))
             {
                 if (!drms_segment_checkscaling(out, seg->bzero, seg->bscale))
                 {
                     fprintf(stderr, "The output array's bzero/bscale values (%f, %f) do not match those of the TAS file (%f, %f).\n", out->bzero, out->bscale, seg->bzero, seg->bscale);
                     status = DRMS_ERROR_INVALIDSCALING;
                     goto bailout;
                 }
             }

             if ((status = drms_fitstas_writeslice(seg->record->env,
                                                   seg,
                                                   filename,
                                                   seg->info->naxis,
                                                   seg->axis,
                                                   start,
                                                   end,
                                                   seg->record->slotnum,
                                                   out)) != DRMS_SUCCESS)
                 goto bailout;

             /* We successfully wrote a slice to a TAS file, so now we have to delete the corresponding .virgin file. This
              * will ensure that we do NOT delete the TAS file during module shutdown. */
             snprintf(virgin, sizeof(virgin), "%s.virgin", filename);
             if (!stat(virgin, &stBuf))
             {
                 /* Virgin file exists, delete it. */
                 unlink(virgin);
             }
         }
          break;
        default:
          return DRMS_ERROR_UNKNOWNPROTOCOL;
     }

     if (out!=arr)
       drms_free_array(out);

     if (seg->info->scope == DRMS_CONSTANT &&
         !seg->info->cseg_recnum) {
        if (seg->record->lifetime == DRMS_TRANSIENT) {
           fprintf(stderr, "Error: cannot set constant segment in a transient record\n");
           goto bailout;
        }
        return drms_segment_set_const(seg);
     }

     return DRMS_SUCCESS;
  }
  else
    return DRMS_ERROR_NULLPOINTER;

 bailout:
  if (out && out!=arr)
    drms_free_array(out);
  fprintf(stderr,"ERROR: Couldn't write data to file '%s'.\n", filename);
  return status;
}

int drms_segment_writeslice(DRMS_Segment_t *seg,
                            DRMS_Array_t *arr,
                            axislen_t *start,
                            axislen_t *end,
                            int autoscale)
{
    return drms_segment_writeslice_ext(seg, arr, start, end, NULL, autoscale);
}

int drms_segment_write_from_file(DRMS_Segment_t *seg, const char *infile) {
  char *filename;            /* filename without path */
  char outfile[DRMS_MAXPATHLEN];
  FILE *in, *out;            /* input and output file stream */
  size_t read_size;          /* number of bytes on last read */
  const unsigned int bufsize = 16*1024;
  char *buf = malloc(bufsize*sizeof(char)); /* buffer for data */

  if (seg->info->scope == DRMS_CONSTANT &&
      seg->info->cseg_recnum) {
    fprintf(stderr, "ERROR in drms_segment_write: constant segment has already"
	    " been initialized. Series = %s.\n",  seg->record->seriesinfo->seriesname);
    return DRMS_ERROR_INVALIDACTION;
  }

  if (seg->record->readonly) {
    fprintf(stderr, "ERROR in drms_segment_write_from_file: Can't use "
	    "on readonly segment\n");
    return DRMS_ERROR_RECORDREADONLY;
  }

  // check protocol
  if (seg->info->protocol != DRMS_GENERIC)  {
    fprintf(stderr, "ERROR in drms_segment_write_from_file: Can't use "
	    "on non-DRMS_GENERIC segment.  Series = %s.\n", seg->record->seriesinfo->seriesname);
    return DRMS_ERROR_INVALIDACTION;
  }

  if ((in = fopen(infile, "r")) == NULL) {
    fprintf(stderr, "Error:Unable to open %s\n", infile);
    goto bailout;
  }
  // strip path from infile
  filename = rindex(infile, '/');
  if (filename)
    filename++;
  else
    filename = infile;

  CHECKSNPRINTF(snprintf(seg->filename, DRMS_MAXSEGFILENAME, "%s", filename), DRMS_MAXSEGFILENAME);
  drms_segment_filename(seg, outfile);
  if ((out = fopen(outfile, "w")) == NULL) {
    fprintf(stderr, "Error:Unable to open %s\n", outfile);
    goto bailout;
  }
  while (1) {
    read_size = fread(buf, 1, bufsize, in);
    if (ferror(in)) {
	 fprintf(stderr, "Error:Read error\n");
	 goto bailout1;
    }
    else if (read_size == 0) {
	 break;              /* end of file */
    }

    fwrite(buf, 1, read_size, out);
  }
  fclose(in);
  fclose(out);
  free(buf);
  buf = NULL;

  if (seg->info->scope == DRMS_CONSTANT &&
      !seg->info->cseg_recnum) {

    if (seg->record->lifetime == DRMS_TRANSIENT) {
      fprintf(stderr, "Error: cannot set constant segment in a transient record\n");
      goto bailout;
    }
    return drms_segment_set_const(seg);
  }

  return DRMS_SUCCESS;

 bailout1:
  unlink(outfile);
 bailout:
  if (buf)
    free(buf);
  seg->filename[0] = '\0';
  return 1;
}

void drms_segment_setblocksize(DRMS_Segment_t *seg, int *blksz)
{
  memcpy(seg->blocksize,blksz,seg->info->naxis*sizeof(int));
}


void drms_segment_getblocksize(DRMS_Segment_t *seg, int *blksz)
{
  memcpy(blksz,seg->blocksize,seg->info->naxis*sizeof(int));
}


/* Set the scaling of the segment such that the values in the array
   can be stored in an (scaled) integer data segment without overflow.
   The bzero/bscale parameters that the array should be scaled by are returned.
*/
void drms_segment_autoscale(DRMS_Segment_t *seg,
			    DRMS_Array_t *arr,
			    double *autobzero,
			    double *autobscale)
{
  int iscale;
  arraylen_t i;
  arraylen_t n;
  double outmin, outmax;
  double inmin, inmax;
  double val, bscale, bzero;

  switch(seg->info->type)
  {
  case DRMS_TYPE_CHAR:
    outmin = (double)SCHAR_MIN+1;
    outmax = (double)SCHAR_MAX;
    break;
  case DRMS_TYPE_SHORT:
    outmin = (double)SHRT_MIN+1;
    outmax = (double)SHRT_MAX;
    break;
  case DRMS_TYPE_INT:
    outmin = (double)INT_MIN+1;
    outmax = (double)INT_MAX;
    break;
  case DRMS_TYPE_LONGLONG:
    outmin = (double)LLONG_MIN+1;
    outmax = (double)LLONG_MAX;
    break;
  case DRMS_TYPE_FLOAT:
  case DRMS_TYPE_DOUBLE:
  case DRMS_TYPE_TIME:
  case DRMS_TYPE_STRING:
    return;
  default:
    fprintf(stderr, "ERROR: Unhandled DRMS type %d\n",(int)seg->info->type);
    XASSERT(0);
  }

  n = drms_array_count(arr);
  /* Does the scaling preserve integers? */
  iscale = (trunc(arr->bscale)==arr->bscale && trunc(arr->bzero)==arr->bzero);
  bzero=0.0;
  bscale=1.0;
  switch(arr->type)
  {
  case DRMS_TYPE_CHAR:
    if (arr->israw || CHAR_MAX>outmax || CHAR_MIN<outmin)
    {
      char *p = (char *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
	/* If the existing scaling preserves integers and fits
	   in the target range, don't mess with it. */
	if ( iscale && inmax<=outmax && inmin>=outmin)
	{
	  bzero = arr->bzero;
	  bscale = arr->bscale;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
      else
      {
	if (inmax<=outmax && inmin>=outmin)
	{
	  bzero = 0.0;
	  bscale = 1.0;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
    }

    *autobzero = bzero;
    *autobscale = bscale;
    break;
  case DRMS_TYPE_SHORT:
    if (arr->israw || SHRT_MAX>outmax || SHRT_MIN<outmin)
    {
      short *p = (short *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
	/* If the existing scaling preserves integers and fits
	   in the target range, don't mess with it. */
	if ( iscale && inmax<=outmax && inmin>=outmin)
	{
	  bzero = arr->bzero;
	  bscale = arr->bscale;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
      else
      {
	if (inmax<=outmax && inmin>=outmin)
	{
	  bzero = 0.0;
	  bscale = 1.0;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
    }

    *autobzero = bzero;
    *autobscale = bscale;
    break;
  case DRMS_TYPE_INT:
    if (arr->israw || INT_MAX>outmax || INT_MIN<outmin)
    {
      int *p = (int *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
	/* If the existing scaling preserves integers and fits
	   in the target range, don't mess with it. */
	if ( iscale && inmax<=outmax && inmin>=outmin)
	{
	  bzero = arr->bzero;
	  bscale = arr->bscale;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
      else
      {
	if (inmax<=outmax && inmin>=outmin)
	{
	  bzero = 0.0;
	  bscale = 1.0;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
    }

    *autobzero = bzero;
    *autobscale = bscale;
    break;
  case DRMS_TYPE_LONGLONG:
    if (arr->israw || LLONG_MAX>outmax || LLONG_MIN<outmin)
    {
      long long *p = (long long *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
	/* If the existing scaling preserves integers and fits
	   in the target range, don't mess with it. */
	if ( iscale && inmax<=outmax && inmin>=outmin)
	{
	  bzero = arr->bzero;
	  bscale = arr->bscale;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
      else
      {
	if (inmax<=outmax && inmin>=outmin)
	{
	  bzero = 0.0;
	  bscale = 1.0;
	}
	else
	{
	  bzero = (inmax+inmin)/2;
	  bscale = (inmax-inmin)/(outmax-outmin);
	}
      }
    }

    *autobzero = bzero;
    *autobscale = bscale;
    break;
  case DRMS_TYPE_FLOAT:
    if (!arr->israw && (seg->info->type==DRMS_TYPE_DOUBLE || seg->info->type==DRMS_TYPE_FLOAT))
    {
       *autobzero = 0.0;
       *autobscale = 1.0;
    }
    else
    {
      float *p = (float *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
      }
      bzero = (inmax+inmin)/2;
      bscale = (inmax-inmin)/(outmax-outmin);

      *autobzero = bzero;
      *autobscale = bscale;
    }
    break;
  case DRMS_TYPE_DOUBLE:
  case DRMS_TYPE_TIME:
    if (!arr->israw && (seg->info->type==DRMS_TYPE_DOUBLE))
    {
       *autobzero = 0.0;
       *autobscale = 1.0;
    }
    else
    {
      double *p = (double *)arr->data;
      inmin = (double) *p;
      inmax = (double) *p++;
      for (i=1; i<n; i++)
      {
	val = (double) *p++;
	if (val<inmin)
	  inmin = val;
	if (val>inmax)
	  inmax = val;
      }
      if (arr->israw)
      {
	inmax = arr->bscale*inmax + arr->bzero;
	inmin = arr->bscale*inmin + arr->bzero;
      }
      bzero = (inmax+inmin)/2;
      bscale = (inmax-inmin)/(outmax-outmin);

      *autobzero = bzero;
      *autobscale = bscale;
    }
    break;
  case DRMS_TYPE_STRING:
    *autobzero = 0.0;
    *autobscale = 1.0;
    return;
  default:
    fprintf(stderr, "ERROR: Unhandled DRMS type %d\n",(int)arr->type);
    XASSERT(0);
  }
}

int drms_segment_segsmatch(const DRMS_Segment_t *s1, const DRMS_Segment_t *s2)
{
   int ret = 1;

   if (s1 && s2)
   {
      int nDims = s1->info->naxis;
      if (nDims == s2->info->naxis)
      {
	 int i = 0;
	 for (; i < nDims; i++)
	 {
	    if (s1->axis[i] != s2->axis[i])
	    {
	       ret = 0;
	       break;
	    }
	 }

	 if (s1->info->protocol == DRMS_TAS && s2->info->protocol == DRMS_TAS)
	 {
	    for (i = 0; ret == 1 && i < nDims; i++)
	    {
	       if (s1->blocksize[i] != s2->blocksize[i])
	       {
		  ret = 0;
		  break;
	       }
	    }
	 }
      }
      else
      {
	 ret = 0;
      }

      if (ret == 1)
      {
	 if ((s1->info->type != s2->info->type) ||
	     (s1->info->protocol != s2->info->protocol) ||
	     (s2->info->scope != s2->info->scope))
	 {
	    ret = 0;
	 }
      }
   }
   else if (s1 || s2)
   {
      ret = 0;
   }

   return ret;
}

static DRMS_Segment_t *TemplateSegFollowLink(DRMS_Segment_t *srcseg, int depth, int *statret)
{
    int status = DRMS_SUCCESS;
    DRMS_Link_t *link = NULL;
    DRMS_Record_t *linktempl = NULL;
    DRMS_Segment_t *tgtseg = NULL;

    /* Fetch link struct. */
    link = (DRMS_Link_t *)hcon_lookup_lower(&srcseg->record->links, srcseg->info->linkname);
    if (link)
    {
        linktempl = drms_template_record(srcseg->record->env, link->info->target_series, &status);

        if (linktempl)
        {
            tgtseg = (DRMS_Segment_t *)hcon_lookup_lower(&linktempl->segments, srcseg->info->target_seg);

            if (tgtseg)
            {
                if (tgtseg->info->islink)
                {
                    if (depth < DRMS_MAXLINKDEPTH)
                    {
                        tgtseg = TemplateSegFollowLink(tgtseg, depth + 1, statret);
                    }
                    else
                    {
                        fprintf(stderr,
                                "WARNING: Max link depth exceeded for segment '%s' in series '%s'.\n",
                                srcseg->info->name,
                                link->info->target_series);
                    }
                }
            }
            else
            {
                if (statret)
                {
                    *statret = DRMS_ERROR_UNKNOWNSEGMENT;
                }
            }
        }
        else
        {
            if (statret)
            {
                *statret = DRMS_ERROR_UNKNOWNSERIES;
            }
        }
    }
    else
    {
        if (statret)
        {
            *statret = DRMS_ERROR_UNKNOWNLINK;
        }
    }

    return tgtseg;
}

DRMS_Segment_t *drms_template_segment_followlink(DRMS_Segment_t *srcseg, int *statret)
{
    return TemplateSegFollowLink(srcseg, 0, statret);
}
