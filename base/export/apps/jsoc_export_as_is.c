// #define DEBUG 1
#define DEBUG 0

/*
 *  jsoc_export_as_is - Generates index.XXX files for dataset export.
 *  Copied and changed from jsoc_info.c
 *  This program is expected to be run in a drms_run script.
 *  cwd is expected to be the export SU.
 *
*/
#include "jsoc_main.h"
#include "drms.h"
#include "drms_names.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "exputil.h"

#define kMaxSegs 1000

ModuleArgs_t module_args[] =
{
  {ARG_STRING, "op", "Not Specified", "<Operation>"},
  {ARG_STRING, "ds", "Not Specified", "<record_set query>"},
  {ARG_INT, "n", "0", "record_set count limit"},
  {ARG_STRING, "seg", "**ALL**", "<comma delimited segment list>"},
  {ARG_STRING, "requestid", "Not Specified", "RequestID string for export management"},
  {ARG_STRING, "method", "url", "Export method"},
  {ARG_STRING, "protocol", "as-is", "export file protocol"},
  {ARG_STRING, "format", "json", "export communication protocol"},
  {ARG_STRING, "filenamefmt", "Not Specified", "export filename format rule"},
  {ARG_FLAG, "h", "0", "help - show usage"},
  {ARG_FLAG, "z", "0", "emit JSON output"},
  {ARG_STRING, "QUERY_STRING", "Not Specified", "AJAX query from the web"},
  {ARG_END}
};

char *module_name = "jsoc_export_as_is";
int nice_intro ()
  {
  int usage = cmdparams_get_int (&cmdparams, "h", NULL);
  if (usage)
    {
    printf ("Usage:\njsoc_export_as_is {-h} "
	"op=<command> ds=<recordset query> {n=0} {key=<keylist>} {seg=<segment_list>}\n"
        "  details are:\n"
	"op=<command> tell which ajax function to execute\n"
	"ds=<recordset query> as <series>{[record specifier]} - required\n"
	"n=<recordset count limit> optional\n"
	"seg=<comma delimited segment list, default is **ALL**>\n"
        "requestid= RequestID string for export management\n"
        "method = Export method, default to url\n"
        "protocol = export file protocol, default to as-is\n"
        "format = export communication protocol, default to json\n"
        "filenamefmt = export filename format rule\n"
	);
    return(1);
    }
  return (0);
  }

#define DIE(msg) \
  {	\
  fprintf(index_txt,"status=1\n");	\
  fprintf(index_txt, "error='%s'\n", msg);	\
  fclose(index_txt); \
  return(1);	\
  }

static int GetSegList(const char *seglistin, DRMS_Record_t *rec, char **segs, int size)
{
   int nsegs = 0;
   char *thisseg = NULL;
   char *restrict seglist = strdup(seglistin);

   if (seglist)
   {
      thisseg=strtok(seglist, ",");

      if (strcmp(thisseg,"**NONE**")==0)
      {
         nsegs = 0;
      }
      else if (strcmp(thisseg, "**ALL**")==0)
      {
         DRMS_Segment_t *seg;
         HIterator_t *hit = NULL;

         while ((seg = drms_record_nextseg(rec, &hit, 1)) != NULL)
         {
            if (nsegs >= size)
            {
               fprintf(stderr, "Segment list truncated - too many segments.\n");
               break;
            }

            segs[nsegs++] = strdup(seg->info->name);
         }

         hiter_destroy(&hit);
      }
      else
      {
         for (; thisseg; thisseg=strtok(NULL,","))
         {
            if (nsegs >= size)
            {
               fprintf(stderr, "Segment list truncated - too many segments.\n");
               break;
            }

            segs[nsegs++] = strdup(thisseg);
         }
      }
   }

   return nsegs;
}

static DRMS_Segment_t *linked_segment(DRMS_Env_t *env, DRMS_Segment_t *template_segment)
{
    DRMS_Segment_t *child_template_segment = NULL;
    DRMS_Link_t *link = NULL;
    DRMS_Record_t *child_template_record = NULL;

    if (template_segment->info->islink)
    {
        link = (DRMS_Link_t *)hcon_lookup_lower(&template_segment->record->links, template_segment->info->linkname);
        if (link)
        {
            child_template_record = (DRMS_Record_t *)hcon_lookup_lower(&env->series_cache, link->info->target_series);
        }

        if (child_template_record)
        {
            child_template_segment = (DRMS_Segment_t *)hcon_lookup_lower(&child_template_record->segments, template_segment->info->target_seg);
        }
    }

    return child_template_segment;
}

static int parse_specification(DRMS_Env_t *env, const char *specification, DRMS_Record_t **template_record_out, LinkedList_t **segments_out)
{
    char *clean_specification = NULL;
    char *all_versions = NULL;
    char **sets = NULL;
    DRMS_RecordSetType_t *set_types = NULL;
    char **series = NULL;
    char **filters = NULL;
    char **segments = NULL;
    int number_sets = 0;
    DRMS_RecQueryInfo_t info;
    char *segment = NULL;
    char *saver = NULL;
    char *clean_segments = NULL;
    char segment_buffer[DRMS_MAXSEGNAMELEN] = {0};
    int drms_status = DRMS_SUCCESS;

    int error = 0;
    DRMS_Record_t *template_record = NULL;
    DRMS_Record_t *template_segment = NULL;
    LinkedList_t *segment_list = NULL;

    base_strip_whitespace(specification, &clean_specification);

    if (drms_record_parserecsetspec_plussegs(clean_specification, &all_versions, &sets, &set_types, &series, &filters, &segments, &number_sets, &info) != DRMS_SUCCESS)
    {
        fprintf(stderr, "invalid specification `%s`\n", specification);
        error = 1;
    }
    else if (number_sets != 1)
    {
        fprintf(stderr, "jsoc_export_as_fits does not support subsetted record-set specifications\n");
        error = 1;
    }

    if (!error)
    {
        if (template_record_out)
        {
            template_record = drms_template_record(env, series[0], &drms_status);

            if (!template_record || drms_status != DRMS_SUCCESS)
            {
                fprintf(stderr, "unknown series `%s`\n", series[0]);
                error = 1;
            }
            else
            {
                *template_record_out = template_record;

                if (segments_out)
                {
                    segment_list = list_llcreate(DRMS_MAXSEGNAMELEN, NULL);

                    if (segment_list)
                    {
                        /* segments[0] contains "{}" if segment filter exists; NULL otherwise */
                        if (segments[0] && *segments[0] != '\0')
                        {
                            clean_segments = strdup(segments[0] + 1);
                            clean_segments[strlen(clean_segments) - 1] = '\0';
                        }

                        if (clean_segments && *clean_segments != '\0')
                        {
                            for (segment = strtok_r(clean_segments, ",", &saver); segment; segment = strtok_r(NULL, ",", &saver))
                            {
                                /* don't follow links */
                                template_segment = hcon_lookup_lower(&(template_record->segments), segment);

                                if (!template_segment)
                                {
                                    fprintf(stderr, "unknown segment `%s`\n", segment);
                                    error = 1;
                                }
                                else
                                {
                                    snprintf(segment_buffer, sizeof(segment_buffer), "%s", segment);
                                    list_llinserttail(segment_list, segment_buffer);
                                }
                            }
                        }

                        *segments_out = segment_list;
                    }
                }
            }
        }
    }

    if (clean_segments)
    {
        free(clean_segments);
        clean_segments = NULL;
    }

    if (clean_specification)
    {
        free(clean_specification);
        clean_specification = NULL;
    }

    drms_record_freerecsetspecarr_plussegs(&all_versions, &sets, &set_types, &series, &filters, &segments, number_sets);

    return error;
}

static int fetch_linked_segments(DRMS_Env_t *env, DRMS_Record_t *template_record, LinkedList_t *segments)
{
    DRMS_Segment_t *template_segment = NULL;
    int number_segments = -1;
    ListNode_t *list_node = NULL;
    char *segment = NULL;
    HIterator_t *current_segment_hit = NULL;
    int b_fetch_linked_segments = -1;

    number_segments = list_llgetnitems(segments);

    b_fetch_linked_segments = 0;
    if (segments && number_segments > 0 && number_segments != hcon_size(&template_record->segments))
    {
        /* a subset of segments is being requested */
        list_llreset(segments);
        while (!b_fetch_linked_segments && (list_node = list_llnext(segments)) != NULL)
        {
            segment = (char *)list_node->data;
            template_segment = (DRMS_Segment_t *)hcon_lookup_lower(&template_record->segments, segment);

            while (template_segment)
            {
                template_segment = linked_segment(env, template_segment);

                if (template_segment)
                {
                    if (!template_segment->info->islink)
                    {
                        b_fetch_linked_segments = 1;
                        break;
                    }
                }
            }
        }
    }
    else
    {
        /* all segments are being requested */
        while (!b_fetch_linked_segments && (template_segment = drms_record_nextseg(template_record, &current_segment_hit, 0)) != NULL)
        {
            while (template_segment)
            {
                template_segment = linked_segment(env, template_segment);

                if (template_segment)
                {
                    if (!template_segment->info->islink)
                    {
                        b_fetch_linked_segments = 1;
                        break;
                    }
                }
            }
        }

        hiter_destroy(&current_segment_hit);
    }

    return b_fetch_linked_segments;
}

/* Module main function. */
int DoIt(void)
{
    char *in;
    char *requestid;
    char *method;
    char *protocol;
    char *format;
    char *filenamefmt;
    char *seglist;
    int segs_listed;

    DRMS_RecordSet_t *recordset;
    DRMS_Record_t *rec;
    char *segs[kMaxSegs];
    int iseg, nsegs = 0;
    int count;
    int RecordLimit = 0;
    int status=0;
    int irec, nrecs;
    long long size;
    FILE *index_txt, *index_data;
    char buf[2*DRMS_MAXPATHLEN];
    char *cwd;

    DRMS_Record_t *template_record = NULL;
    LinkedList_t *segments = NULL;
    int b_fetch_linked_segments = -1;

    in = (char *)cmdparams_get_str (&cmdparams, "ds", NULL);
    requestid = (char *)cmdparams_get_str (&cmdparams, "requestid", NULL);
    format = (char *)cmdparams_get_str (&cmdparams, "format", NULL);
    filenamefmt = (char *)cmdparams_get_str (&cmdparams, "filenamefmt", NULL);
    method = (char *)cmdparams_get_str (&cmdparams, "method", NULL);
    protocol = (char *)cmdparams_get_str (&cmdparams, "protocol", NULL);
    seglist = (char *)strdup (cmdparams_get_str (&cmdparams, "seg", NULL));
    RecordLimit = cmdparams_get_int (&cmdparams, "n", NULL);
    segs_listed = strcmp (seglist, "Not Specified");

    index_txt = fopen("index.txt", "w");
    fprintf(index_txt, "# JSOC Export File List\n");
    fprintf(index_txt, "version=1\n");
    fprintf(index_txt, "requestid=%s\n", requestid);
    fprintf(index_txt, "method=%s\n", method);
    fprintf(index_txt, "protocol=%s\n", protocol);
    fprintf(index_txt, "wait=0\n");

    /* parse specification */
    if (parse_specification(drms_env, in, &template_record, &segments))
    {
        DIE("[ __main__ ] unable to parse record-set specification");
    }

    b_fetch_linked_segments = fetch_linked_segments(drms_env, template_record, segments);
    list_llfree(&segments);

    recordset = drms_open_records2(drms_env, in, NULL, 0, RecordLimit, 1, &status);

    if (!recordset)
    {
        DIE("[ __main__ ] unable to open records");
    }

    /* stage records to reduce number of calls to SUMS. */
    /* There is no call to drms_open_recordset(), so staging happens when drms_stage_records() is called.
     * With drms_open_recordset(), you have to call drms_recordset_fetchnext() to stage each chunk on-demand. */
    if (b_fetch_linked_segments)
    {
        status = drms_stage_records(recordset, 1, 0);
    }
    else
    {
        status = drms_stage_records_dontretrievelinks(recordset, 1);
    }

    if (status != DRMS_SUCCESS)
    {
        DIE("[ __main__ ] unable to stage records");
    }

    nrecs = recordset->n;
    if (nrecs == 0)
    {
        fprintf(index_txt, "count=0\n");
        fprintf(index_txt, "size=0\n");
        fprintf(index_txt, "status=0\n");
        fclose(index_txt);
        return(0);
    }

    index_data = fopen("index.data", "w+");

    /* loop over set of selected records */
    count = 0;
    size = 0;

    for (irec = 0; irec < nrecs; irec++)
    {
        char recquery[DRMS_MAXQUERYLEN];
        char recpath[DRMS_MAXPATHLEN];

        rec = drms_recordset_fetchnext(drms_env, recordset, &status, NULL, NULL); /* pointer to current record */

        if (!rec)
        {
            /* Exit rec loop - last record was fetched last time. */
            break;
        }

        if (irec == 0 && segs_listed)
        {
            /* get list of segments to show for each record */
            nsegs = GetSegList(seglist, rec, segs, kMaxSegs);
        }

        drms_sprint_rec_query(recquery,rec);

        if (drms_record_directory (rec, recpath, 1))
        {
            continue;
        }

        if (strlen(recpath) < 10)
        {
            continue;
        }

        /* now get desired segments */

        DRMS_Segment_t *tgtseg = NULL; /* target seg, if the source seg is a linked seg. */
        for (iseg = 0; iseg < nsegs; iseg++)
        {
            DRMS_Segment_t *rec_seg_iseg = drms_segment_lookup (rec, segs[iseg]);
            char path[DRMS_MAXPATHLEN];
            char query[DRMS_MAXQUERYLEN];
            char filename[DRMS_MAXPATHLEN];
            struct stat filestat;

            if (!rec_seg_iseg)
            {
                DIE("jsoc_export_as_is: attempt to lookup unidentified segment");
            }

            // Get record query with segment name appended
            strncpy(query, recquery, DRMS_MAXQUERYLEN);
            strncat(query, "{", DRMS_MAXQUERYLEN);
            strncat(query, segs[iseg], DRMS_MAXQUERYLEN);
            strncat(query, "}", DRMS_MAXQUERYLEN);

            if (*rec_seg_iseg->filename != '\0')
            {
                // If there is no segment file, go on to the next segment (or record if this was the last segment)
                // Get paths to segment files
                strncpy(path, recpath, DRMS_MAXPATHLEN);
                strncat(path, "/", DRMS_MAXPATHLEN);
                strncat(path, rec_seg_iseg->filename, DRMS_MAXPATHLEN);
            }
            else
            {
                /* It could be the case that the record was created without saving the seg->filename. In that case, we default to
                * using the segment name as the file name. */
                strncpy(path, recpath, DRMS_MAXPATHLEN);
                strncat(path, "/", DRMS_MAXPATHLEN);
                strncat(path, rec_seg_iseg->info->name, DRMS_MAXPATHLEN);
            }

            if (stat(path, &filestat) == 0) // only make links for existing files!
            {
                if (S_ISDIR(filestat.st_mode))
                {
                    // Segment is directory, get size == for now == use system "du"
                    char cmd[DRMS_MAXPATHLEN+100];
                    FILE *du;
                    long long dirsize;
                    sprintf(cmd,"/usr/bin/du -s -b %s", path);
                    du = popen(cmd, "r");
                    if (du)
                    {
                        if (fscanf(du,"%lld",&dirsize) == 1)
                        size += dirsize;
                        pclose(du);
                    }
                }
                else
                {
                    size += filestat.st_size;
                }

                /* Make a symlink for each selected file */
                if (rec_seg_iseg->info->islink)
                {
                    if ((tgtseg = drms_segment_lookup(rec, rec_seg_iseg->info->name)) == NULL)
                    {
                        DIE("Unable to locate target segment.\n");
                    }
                }

                exputl_mk_expfilename(rec_seg_iseg, tgtseg, strcmp(filenamefmt,"Not Specified") ? filenamefmt : NULL, filename);
                if (strcmp(method,"ftp")==0)
                {
                    char tmp[DRMS_MAXPATHLEN];
                    sprintf(tmp,"/export%s", path);
                    symlink(tmp,filename);
                }
                else
                {
                    symlink(path,filename);
                }

                /* write a line for each record to each output file type wanted */

                fprintf(index_data, "%s\t%s\n",query,filename);
                count += 1;
            }
            else
            {
                fprintf(index_data, "%s\tNoDataFile\n",query);
            }
        } // segment loop
    } // record loop

    if (seglist)
    {
        free(seglist);
        seglist = NULL;
    }

    if (size > 0 && size < 1024*1024)
    {
        size = 1024*1024;
    }

    size /= 1024*1024;

    /* Finished.  Clean up and exit. */
    fprintf(index_txt, "count=%d\n",count);
    fprintf(index_txt, "size=%lld\n",size);
    fprintf(index_txt, "status=0\n");
    cwd = getcwd(NULL, 0);
    fprintf(index_txt,"dir=%s\n", ((strncmp("/auto", cwd,5) == 0) ? cwd+5 : cwd));
    fprintf(index_txt, "# DATA\n");
    rewind(index_data);

    while (fgets(buf, DRMS_MAXPATHLEN*2, index_data))
    {
        fputs(buf, index_txt);
    }

    fclose(index_txt);
    fclose(index_data);
    unlink("index.data");

    drms_close_records(recordset, DRMS_FREE_RECORD);
    return(0);
}
