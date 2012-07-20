#include "jsoc_main.h"

char *module_name = "jsoc_export_clone";

typedef enum
{
    kExpCloneErr_Success = 0,
    kExpCloneErr_Argument,
    kExpCloneErr_UnknownSeries,
    kExpCloneErr_OutOfMemory,
    kExpCloneErr_NoTemplate,
    kExpCloneErr_CantCreateProto,
    kExpCloneErr_CantCreateSeries,
    kExpCloneErr_CantParseKeyDesc,
    kExpCloneErr_LibDRMS
} ExpError_t;

#define kArgSeriesIn   "dsin"
#define kArgSeriesOut  "dsout"
#define kArgRetention  "ret"
#define kArgArchive    "arch"
#define kNotSpec       "NOTSPECIFIED"

/* Possibly new keywords for series being created. */
#define kKeyReqID      "RequestID"
#define kKeyHistory    "HISTORY"
#define kKeyComment    "COMMENT"

ModuleArgs_t module_args[] =
{
    {ARG_STRING,  kArgSeriesIn,  NULL,       "Input series name."},
    {ARG_STRING,  kArgSeriesOut, kNotSpec,   "(Optional) Output series name."},
    {ARG_INT,     kArgRetention, "10",       "(Optional) Output-series' SU retention."},
    {ARG_STRING,  kArgArchive,   "-1",       "(Optional) Output-series' SU archive flag."},
    {ARG_END,     NULL,          NULL,       NULL}
};

static DRMS_Record_t *CopySeriesTemplate(DRMS_Env_t *env, const char *in, ExpError_t *status)
{
    ExpError_t err = kExpCloneErr_Success;
    int drmsstat = DRMS_SUCCESS;
    
    DRMS_Record_t *proto = NULL;
    DRMS_Record_t *template = NULL; 
    
    /* Ensure series exists. */
    if (!drms_series_exists(env, in, &drmsstat) || drmsstat)
    {
        fprintf(stderr, "Input series '%s' does not exist.\n", in);
        err = kExpCloneErr_UnknownSeries;
    }
    else
    {
        /* Get the read-only input series template record. */
        template = drms_template_record(env, in, &drmsstat);
        
        if (!template || drmsstat)
        {
            fprintf(stderr, "Unable to obtain template record for series '%s'.\n", in);
            err = kExpCloneErr_NoTemplate;
        }
        else
        {
            /* drms_create_recproto() SHALLOW-COPIES the keyword->info structs! */
            proto = drms_create_recproto(template, &drmsstat);
        }
        
        if (!proto || drmsstat)
        {
            fprintf(stderr, "Unable to obtain record prototype for series '%s'.\n", in);
            err = kExpCloneErr_CantCreateProto;
        }
    }
    
    if (status)
    {
        *status = err;
    }
    
    return proto;
}

static ExpError_t AddAKey(const char *keyname, 
                          DRMS_Record_t *prototype, 
                          const char *desc,
                          int intprime,
                          int extprime,
                          int rank)
{
    ExpError_t rv = kExpCloneErr_Success;
    int drmsstat = DRMS_SUCCESS;
    
    if (!drms_keyword_lookup(prototype, keyname, 0))
    {
        DRMS_Keyword_t *tKey = NULL;
        DRMS_Keyword_t finalkey;
        HContainer_t *keys = NULL;
        HIterator_t *hit = NULL;
        
        keys = drms_parse_keyworddesc(prototype->env, desc, &drmsstat);
        if (!keys || drmsstat)
        {
            fprintf(stderr, "Failed to parse keyword description '%s'.\n", desc);
            rv = kExpCloneErr_CantParseKeyDesc;
        }
        else if (hcon_size(keys) == 1)
        {
            /* Set the pointer from the key struct to the containing record. */
            hit = hiter_create(keys);
            
            if (hit)
            {
                tKey = (DRMS_Keyword_t *)hiter_getnext(hit);
                tKey->record = prototype;
                
                /* Set the keyword's rank. */
                tKey->info->rank = rank; /* 0-based */
                tKey->info->kwflags |= (rank + 1) << 16; /* 1-based - does directly into db. */
                
                /* Set 'prime' flags. */
                if (intprime)
                {
                    drms_keyword_setintprime(tKey);
                }
                
                if (extprime)
                {
                    drms_keyword_setextprime(tKey);
                }
                
                /* Put the key into the prototype's keyword container. But first copy the keyword struct to 
                 * a new struct, deep-copying any string value. When we free the keys container, this will result in 
                 * any string keyword value to be freed (keys was set up with a deep-free function - see 
                 * drms_free_keyword_struct). */
                finalkey.record = tKey->record;
                finalkey.info = tKey->info;
                
                if (finalkey.info->type == DRMS_TYPE_STRING)
                {
                    finalkey.value.string_val = strdup(tKey->value.string_val);
                }
                else
                {
                    finalkey.value = tKey->value;
                }
                
                hcon_insert_lower(&prototype->keywords, keyname, &finalkey);
                
                if (intprime)
                {
                    /* When setting up pointer to prime key, must use the key in prototype->keywords. */
                    tKey = (DRMS_Keyword_t *)hcon_lookup_lower(&prototype->keywords, keyname);
                    if (tKey)
                    {
                        prototype->seriesinfo->pidx_keywords[prototype->seriesinfo->pidx_num++] = tKey;
                    }
                    else
                    {
                        rv = kExpCloneErr_LibDRMS;
                    }
                }
                
                hiter_destroy(&hit);
            }
        }
        else
        {
            /* Error */
            fprintf(stderr, "Failed to parse keyword description '%s'.\n", desc);
            rv = kExpCloneErr_CantParseKeyDesc;
        }
        
        if (keys)
        {
            /* Free the keys container. This will deep-free any string values, but it will not free the info
             * struct. */
            hcon_destroy(&keys);
        }
    }

    return rv;
}

int DoIt(void) 
{
    ExpError_t err = kExpCloneErr_Success;

    int drmsstat = DRMS_SUCCESS;
    char *seriesin = NULL;
    const char *seriesout = NULL;
    char *name = NULL;
    int retention = -1;
    int archive = -1;
    DRMS_Record_t *copy = NULL;
    DRMS_Segment_t *seg = NULL;
    HIterator_t *lastseg = NULL;
    int hirank = -1;
    
    /* seriesin is the input series. */
    seriesin = strdup(cmdparams_get_str(&cmdparams, kArgSeriesIn, NULL));
    
    /* seriesout is the name of the series to create. */
    seriesout = cmdparams_get_str(&cmdparams, kArgSeriesOut, NULL);
    
    if (strcmp(seriesout, kNotSpec) == 0)
    {
        /* If name is not specified on the cmd-line, then default to concatenating 
         * seriesin and "_mod". */
        size_t nsize = strlen(seriesin) + 16;
        name = calloc(nsize, 1);
        name = base_strcatalloc(name, seriesin, &nsize);
        name = base_strcatalloc(name, "_mod", &nsize);
    }
    else
    {
        name = strdup(seriesout);
    }
    
    /* retention is name's jsd retention value. */
    retention = cmdparams_get_int(&cmdparams, kArgRetention, NULL);
    
    /* archive is name's jsd archive value. */
    archive = cmdparams_get_int(&cmdparams, kArgArchive, NULL);
    
    /* Get a COPY of the input series template record. */
    copy = CopySeriesTemplate(drms_env, seriesin, &err);
    
    if (!copy || err)
    {
        fprintf(stderr, "Unable to copy template record for series '%s'.\n", seriesin);
        if (!err)
        {
            err = kExpCloneErr_CantCreateProto;
        }
    }
    else
    {
        /* unitsize will match the unitsize of the input series. */
        /* tapegroup will match the tapegroup of the input series, but will not
         * matter, since archive == -1. */
        copy->seriesinfo->archive = archive;
        copy->seriesinfo->retention = retention;
        
        hirank = drms_series_gethighestkeyrank(drms_env, seriesin, &drmsstat);
        if (drmsstat || hirank == -1)
        {
            hirank = 0;
        }
        
        /* Add prime keyword RequestID, if it doesn't already exist. */
        err = AddAKey(kKeyReqID, 
                      copy, 
                      "Keyword:RequestID, string, variable, record, \"Invalid RequestID\", %s, NA, \"The export request identifier, if this record was inserted while an export was being processed.\"", 
                      1, 
                      1, 
                      1 + hirank++);

        /* Add keywords HISTORY and COMMENT, if they don't exist. */
        if (err == kExpCloneErr_Success)
        {
            err = AddAKey(kKeyHistory, 
                          copy, 
                          "Keyword:HISTORY, string, variable, record, \"No history\", %s, NA, \"The processing history of the data.\"", 
                          0, 
                          0, 
                          1 + hirank++);
        }
        
        if (err == kExpCloneErr_Success)
        {
            err = AddAKey(kKeyComment, 
                          copy, 
                          "Keyword:COMMENT, string, variable, record, \"No comment\", %s, NA, \"Commentary on the data processing.\"", 
                          0, 
                          0, 
                          1 + hirank++);
        }
        
        /* If the first input FITS data segment does not have a VARDIM segment scope, then make it so. */
        if (err == kExpCloneErr_Success)
        {
            while ((seg = drms_record_nextseg(copy, &lastseg, 0)))
            {
                if (seg->info->protocol == DRMS_FITS)
                {
                    if (seg->info->scope != DRMS_VARDIM)
                    {
                        seg->info->scope = DRMS_VARDIM;
                        memset(seg->axis, 0, sizeof(seg->axis));
                    }
                    
                    break;
                }
            }
            
            if (lastseg)
            {
                hiter_destroy(&lastseg);
            }
            
            /* If the segment contains integer data, then the bzero and bscale values of the original series will suffice, 
             * and that is what seg contains. If they are float data, then bzero and bscale are ignored. */
        }
        
        if (err == kExpCloneErr_Success)
        {
            /* drms_create_series_fromprototype() will first copy keywords with drms_copy_keyword_struct().
             * This latter function shallow-copies each keyword's info struct. */
            if (drms_create_series_fromprototype(&copy, name, 0))
            {
                err = kExpCloneErr_CantCreateSeries;
            }
        }
    }

    if (name)
    {
        free(name);
    }
    
    if (seriesin)
    {
        free(seriesin);
    }
    
    return err;
}