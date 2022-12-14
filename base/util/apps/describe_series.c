/**
\defgroup describe_series describe_series - print summary information about a series
@ingroup drms_util

\brief Print detailed structure information about a series

\par Synopsis:

\code
describe_series [-jGEN_FLAGS] seriesname
\endcode

Print the global information about the data series including summary
information about:
 - the number of records 
 - the highest record number
 - the number of records with distinct primary index
 - the total disk space used, average bytes per record on disk
 - the estimate bytes per record in memory
 - the range of prime key values

\par Flags:
\c -j: print out series information in JSD format.

\par GEN_FLAGS: 
Ubiquitous flags present in every module.
\ref jsoc_main

\param seriesname

\sa
create_series delete_series modify_series show_info jsoc_info

*/
#include "drms.h"
#include "jsoc_main.h"

/* Command line parameter values. */
ModuleArgs_t module_args[] = { 
  {ARG_END}
};

char *module_name = "describe_series";
#ifdef NEED_JSD_STUFF
void drms_keyword_print_jsd(DRMS_Keyword_t *key) {
    printf("Keyword:%s",key->info->name);
    if (key->info->islink) {
      printf(", link, %s, %s, %s\n", key->info->linkname, 
	     key->info->target_key,
	     key->info->description);
    } else {
      printf(", %s", drms_type2str(key->info->type));
      int stat;
      const char *rscope = drms_keyword_getrecscopestr(key, &stat);
      fprintf(stdout, ", %s", stat == DRMS_SUCCESS ? rscope : NULL);
      if (key->info->per_segment) 
	printf(", segment");
      else 
	printf(", record");
      printf(", ");
      if (key->info->type == DRMS_TYPE_STRING) {
	char qf[DRMS_MAXFORMATLEN+2];
	sprintf(qf, "\"%s\"", key->info->format);
	printf(qf, key->value.string_val);
      }
      else 
	drms_keyword_printval(key);      
      if (key->info->unit[0] != ' ') {
	printf(", %s, %s, \"%s\"", key->info->format,
	       key->info->unit,
	       key->info->description);
      } else {
	printf(", %s, none, \"%s\"", key->info->format,
	       key->info->description);
      }
    }
    printf("\n");
}

void drms_segment_print_jsd(DRMS_Segment_t *seg) {
  int i;
  printf("Data: %s, ", seg->info->name);
  if (seg->info->islink) {
    printf("link, %s, %s", seg->info->linkname, seg->info->target_seg);
    if (seg->info->naxis) {
      printf(", %d", seg->info->naxis);
      printf(", %d", seg->axis[0]);
      for (i=1; i<seg->info->naxis; i++) {
	printf(", %d", seg->axis[i]);
      }
    }
  } else {
    switch(seg->info->scope)
      {
      case DRMS_CONSTANT:
	printf("constant");
	break;
      case DRMS_VARIABLE:
	printf("variable");
	break;
      case DRMS_VARDIM:
	printf("vardim");
	break;
      default:
	printf("Illegal value: %d", (int)seg->info->scope);
      }
    printf(", %s, %d", drms_type2str(seg->info->type), seg->info->naxis);
    if (seg->info->naxis) {
      printf(", %d", seg->axis[0]);
      for (i=1; i<seg->info->naxis; i++) {
	printf(", %d", seg->axis[i]);
      }
    }
    printf(", %s, ", seg->info->unit);
    char *protstr = drms_prot2str(seg->info->protocol);
    if (protstr)
    {
       printf(protstr);
    }
    else
    {
       printf("Illegal protocol: %d", (int)seg->info->protocol);
    }
  }
  printf(", \"%s\"\n", seg->info->description);
}

void drms_link_print_jsd(DRMS_Link_t *link) {
  printf("Link: %s, %s, ", link->info->name, link->info->target_series);
  if (link->info->type == STATIC_LINK)
    printf("static");
  else
    printf("dynamic");
  printf(", \"%s\"\n", link->info->description);
}


void print_jsd(DRMS_Record_t *rec) {
  const int fwidth=17;
  int i;
  HIterator_t hit;
  DRMS_Link_t *link;
  DRMS_Keyword_t *key;
  DRMS_Segment_t *seg;

  printf("#=====General Series Information=====\n");
  printf("%-*s\t%s\n",fwidth,"Seriesname:",rec->seriesinfo->seriesname);
  printf("%-*s\t\"%s\"\n",fwidth,"Author:",rec->seriesinfo->author);
  printf("%-*s\t%s\n",fwidth,"Owner:",rec->seriesinfo->owner);
  printf("%-*s\t%d\n",fwidth,"Unitsize:",rec->seriesinfo->unitsize);
  printf("%-*s\t%d\n",fwidth,"Archive:",rec->seriesinfo->archive);
  printf("%-*s\t%d\n",fwidth,"Retention:",rec->seriesinfo->retention);
  printf("%-*s\t%d\n",fwidth,"Tapegroup:",rec->seriesinfo->tapegroup);

  int npkeys = 0;
  char **extpkeys = 
    drms_series_createpkeyarray(rec->env, rec->seriesinfo->seriesname, &npkeys, NULL);
  if (extpkeys && npkeys > 0)
  {
     printf("%-*s\t%s",fwidth,"Index:",extpkeys[0]);
     for (i=1; i<npkeys; i++)
       printf(", %s", extpkeys[i]);
     printf("\n");
  }

  if (extpkeys)
  {
     drms_series_destroypkeyarray(&extpkeys, npkeys);
  }

  printf("%-*s\t%s\n",fwidth,"Description:",rec->seriesinfo->description);
  printf("\n#=====Links=====\n");
  hiter_new_sort(&hit, &rec->links, drms_linke_ranksort); 
  while( (link = (DRMS_Link_t *)hiter_getnext(&hit)) )
    drms_link_print_jsd(link);

  printf("\n#=====Keywords=====\n");
  hiter_new_sort(&hit, &rec->keywords, drms_keyword_ranksort);
  while( (key = (DRMS_Keyword_t *)hiter_getnext(&hit)) )
    drms_keyword_print_jsd(key);

  printf("\n#=====Segments=====\n");
  hiter_new_sort(&hit, &rec->segments, drms_segment_ranksort);
  while( (seg = (DRMS_Segment_t *)hiter_getnext(&hit)) )
    drms_segment_print_jsd(seg);
}
#endif
     
int DoIt(void) {
  int status;
  int jsd;
  DRMS_Record_t *template;
  char *series;
  char query[1024];
  DB_Text_Result_t *qres;
  DB_Binary_Result_t *bres;

  /* Parse command line parameters. */
  if (cmdparams_numargs (&cmdparams) < 2) goto usage;

  /* Get series name. */
  series  = cmdparams_getarg(&cmdparams, 1);

  /* Read the whole description into memory. */
  template = drms_template_record(drms_env, series, &status);
  if (template==NULL)
  {
    printf("Series '%s' does not exist. drms_template_record returned "
	   "status=%d\n",series,status);
    return 1;
  }

  jsd = cmdparams_exists(&cmdparams,"j");
  if (jsd) {
    drms_jsd_print(drms_env, series);
    goto done;
  }
  /* Print out the template record. */
    drms_print_record(template);

  printf("======================================================================\n");
  strtolower(series);  

  /* Print the last record number in the associated sequence table. */
  /*
  printf("Last record number          = %lld\n",
	 drms_sequence_getlast(drms_env->session, series));
  */
  sprintf(query, "select max(recnum) from %s",series);
  if ((qres = drms_query_txt(drms_env->session, query)) && 
      qres->num_rows>0 &&
      qres->field[0][0][0])
  {
    printf("Last record number = %s\n", qres->field[0][0]);
  }
  db_free_text_result(qres);

  long long rec_cnt;
  // sprintf(query, "select reltuples from pg_class where relname='%s'",series);
  sprintf(query, "select count(recnum) from %s",series);
  if ((qres = drms_query_txt(drms_env->session, query)) && qres->num_rows>0)
  {
    printf("Number of records = %s\n", qres->field[0][0]);
    rec_cnt = atoll(qres->field[0][0]);
  }
  db_free_text_result(qres);

  if (template->seriesinfo->pidx_num) {
    char *p = query;
    p += sprintf(p, "select %s from %s group by %s", (template->seriesinfo->pidx_keywords[0])->info->name, series, (template->seriesinfo->pidx_keywords[0])->info->name);
    for (int i=1; i<template->seriesinfo->pidx_num; i++) {
      p += sprintf(p, ", %s", (template->seriesinfo->pidx_keywords[i])->info->name);
    }
    if ((qres = drms_query_txt(drms_env->session, query)) && qres->num_rows>0)
      {
	printf("Number of records with distinct primary index = %u\n",qres->num_rows);
      }
    db_free_text_result(qres);
  }

  sprintf(query, "select pg_size_pretty(pg_total_relation_size('%s'))", series);
  if ((qres = drms_query_txt(drms_env->session, query)) && qres->num_rows>0)    {
    printf("Total disk space used: %s\n", qres->field[0][0]);
  }
  db_free_text_result(qres);

  if (rec_cnt) {
    sprintf(query, "select pg_total_relation_size('%s')", series);
    if ((qres = drms_query_txt(drms_env->session, query)) && qres->num_rows>0)    {
      double tsize = atoll(qres->field[0][0]);
      printf("Average bytes per record on disk: %.2f\n", tsize/rec_cnt);
    }
    db_free_text_result(qres);
  }

  printf("Bytes per record in memory (est.) = %lld\n", 
	 drms_record_memsize(template));

  for (int i=0; i<template->seriesinfo->pidx_num; i++) {
    char *name = (template->seriesinfo->pidx_keywords[i])->info->name;

    DRMS_Type_t type = (template->seriesinfo->pidx_keywords[i])->info->type;

    sprintf(query, "select min(%s),max(%s) from %s", name, name, series);
    if ((bres = drms_query_bin(drms_env->session, query)) && 
	bres->num_rows>0) {
      DRMS_Type_Value_t min, max;
      if (type == DRMS_TYPE_STRING) {
	min.string_val = NULL;
	max.string_val = NULL;
      }
      if (!db_binary_field_is_null(bres, 0, 0) &&
	  !db_binary_field_is_null(bres, 0, 1)) {
     	drms_copy_db2drms(type, &min,
			  db_binary_column_type(bres, 0), 
			  db_binary_field_get(bres, 0, 0)); 
	drms_copy_db2drms(type, &max,
			  db_binary_column_type(bres, 1), 
			  db_binary_field_get(bres, 0, 1)); 
	printf("%s: (", name);
	drms_printfval(type, &min);
	printf(", ");
	drms_printfval(type, &max);      
	printf(")\n");
	if (type == DRMS_TYPE_STRING) {
	  free(min.string_val);
	  free(max.string_val);
	}
      }
    }
    db_free_binary_result(bres);
  }   

 done:
  return 0;

  usage:
  printf("Usage: %s seriesname\n", cmdparams_getarg (&cmdparams, 0));
  return 1;
}
    
