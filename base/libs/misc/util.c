//#if defined(__linux__) && __linux__
//#define _GNU_SOURCE
//#endif /* LINUX */
#include "jsoc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include "util.h"
#include "xassert.h"
#include "xmem.h"
#include "hcontainer.h"

#define ISUPPER(X) (X >= 0x41 && X <= 0x5A)
#define ISLOWER(X) (X >= 0x61 && X <= 0x7A)
#define ISDIGIT(X) (X >= 0x30 && X <= 0x39)
#define DRMS_MAXNAMELEN 32

char *kKEYNAMERESERVED[] =
{
   "_index",
   "ALL",
   "ANALYSE",
   "ANALYZE",
   "AND",
   "ANY",
   "ARRAY",
   "AS",
   "ASC",
   "ASYMMETRIC",
   "BOTH",
   "CASE",
   "CAST",
   "CHECK",
   "COLLATE",
   "COLUMN",
   "CONSTRAINT",
   "CREATE",
   "CURRENT_DATE",
   "CURRENT_ROLE",
   "CURRENT_TIME",
   "CURRENT_TIMESTAMP",
   "CURRENT_USER",
   "DEFAULT",
   "DEFERRABLE",
   "DESC",
   "DISTINCT",
   "DO",
   "ELSE",
   "END",
   "EXCEPT",
   "FALSE",
   "FOR",
   "FOREIGN",
   "FROM",
   "GRANT",
   "GROUP",
   "HAVING",
   "IN",
   "INITIALLY",
   "INTERSECT",
   "INTO",
   "LEADING",
   "LIMIT",
   "LOCALTIME",
   "LOCALTIMESTAMP",
   "NEW",
   "NOT",
   "NULL",
   "OFF",
   "OFFSET",
   "OLD",
   "ON",
   "ONLY",
   "OR",
   "ORDER",
   "PLACING",
   "PRIMARY",
   "REFERENCES",
   "RETURNING",
   "SELECT",
   "SESSION_USER",
   "SOME",
   "SYMMETRIC",
   "TABLE",
   "THEN",
   "TO",
   "TRAILING",
   "TRUE",
   "UNION",
   "UNIQUE",
   "USER",
   "USING",
   "WHEN",
   "WHERE",
   "AUTHORIZATION",
   "BETWEEN",
   "BINARY",
   "CROSS",
   "FREEZE",
   "FULL",
   "ILIKE",
   "INNER",
   "IS",
   "ISNULL",
   "JOIN",
   "LEFT",
   "LIKE",
   "NATURAL",
   "NOTNULL",
   "OUTER",
   "OVERLAPS",
   "RIGHT",
   "SIMILAR",
   "VERBOSE",
   ""
};

HContainer_t *gCleanup = NULL;
HContainer_t *gReservedDRMS = NULL;

typedef enum
{
     kKwCharFirst = 0,
     kKwCharNew,
     kKwCharError
} KwCharState_t;

// To extract namespace from a fully qulified name
char *ns(const char *name) {
   char *nspace = strdup(name);
   char *pc = strrchr(nspace, '.');
   if (pc) {
      *pc = '\0';
   }
   return nspace;
}

void copy_string(char **dst, char *src)
{
  XASSERT((src!=NULL));
  XASSERT(*dst != src); /* Probably a mistake. */
  if (*dst)
    free(*dst);
  *dst = strdup(src);
}

void strtolower(char *str)
{
  int n,i;
  n= strlen(str);
  for (i=0;i<n;i++)
    str[i] = (char)tolower(str[i]);
}

void strtoupper(char *str)
{
  int n,i;
  n= strlen(str);
  for (i=0;i<n;i++)
    str[i] = (char)toupper(str[i]);
}

/* Always NULL-terminates dst */
size_t base_strlcat(char *dst, const char *src, size_t size)
{
   size_t max = size - strlen(dst) - 1; /* max non-NULL can add */
   size_t start = strlen(dst);

   if (max > 0)
   {
      snprintf(dst + start, max + 1, "%s", src); /* add 1 to max for NULL */
   }

   return start + strlen(src);
}

/* sizedst is the currently allocated size of dst */
void *base_strcatalloc(char *dst, const char *src, size_t *sizedst)
{
    size_t srclen = strlen(src);
    size_t dstlen = strlen(dst);
    void *retstr = NULL;
    void *tmp = NULL;

    while (srclen > *sizedst - dstlen - 1)
    {
        if (!tmp)
        {
           tmp = dst;
        }

        tmp = realloc(tmp, *sizedst * 2);
        if (tmp)
        {
            *sizedst *= 2;
            retstr = tmp;
        }
        else
        {
            break;
        }
    }

    if (!retstr)
    {
        retstr = dst;
    }

    if (retstr)
    {
        base_strlcat(retstr, src, *sizedst);
    }

    return retstr;
}

/* Returns a newly allocated string that contains the original string with all instances of
 * the 'repl' string replaced with the string 'with'. */
char *base_strreplace(const char *text, const char *orig, const char *repl)
{
   char *result; // the return string
   const char *replacement = NULL;
   char *ins;    // start, in text, of the next original substring to be replaced
   char *pc;
   const char *pcin;
   size_t lenorig;  // length of original substring
   size_t lenrepl;  // length of replacement substring
   size_t lenprefix; // distance between repl and end of last repl
   int count;    // number of instances of the 'repl' string in 'orig'

   XASSERT(text && orig && strlen(orig) > 0);

   if (text && orig && strlen(orig) > 0)
   {
      lenorig = strlen(orig);
      replacement = (repl == NULL ? "" : repl);
      lenrepl = strlen(replacement);

      for (count = 0, pc = strstr(text, orig), ins = pc; ins && (pc = strstr(ins, orig)); count++)
      {
         ins = pc + lenorig;
      }

      if (count > 0)
      {
         result = malloc(strlen(text) + (lenrepl - lenorig) * count + 1);
         pc = result;
         pcin = text;

         while (count--)
         {
            ins = strstr(pcin, orig);
            lenprefix = ins - pcin;
            strncpy(pc, pcin, lenprefix);
            pc += lenprefix;
            strncpy(pc, replacement, lenrepl);
            pc += lenrepl;
            pcin += lenprefix + lenorig;
         }

         strncpy(pc, pcin, strlen(pcin));
         *(pc + strlen(pcin)) = '\0';
      }
   }

   return result;
}

/* Returns a newly allocated string that contains the original string ('text') with all instances of
 * the 'orig' string replaced with the string 'repl'.
 *
 * This is a case-insenstive version of base_strreplace(). */
char *base_strcasereplace(const char *text, const char *orig, const char *repl)
{
    char *result = NULL; // the return string
    const char *replacement = NULL;
    char *ins;    // start, in text, of the next original substring to be replaced
    char *pc;
    const char *pcin;
    size_t lenorig;  // length of original substring
    size_t lenrepl;  // length of replacement substring
    size_t lenprefix; // distance between repl and end of last repl
    int count;    // number of instances of the 'repl' string in 'orig'

    XASSERT(text && orig && strlen(orig) > 0);

    if (text && orig && strlen(orig) > 0)
    {
        lenorig = strlen(orig);
        replacement = (repl == NULL ? "" : repl);
        lenrepl = strlen(replacement);

        for (count = 0, pc = strcasestr(text, orig), ins = pc; ins && (pc = strcasestr(ins, orig)); count++)
        {
            ins = pc + lenorig;
        }

        if (count > 0)
        {
            result = malloc(strlen(text) + (lenrepl - lenorig) * count + 1);
            pc = result;
            pcin = text;

            while (count--)
            {
                ins = strcasestr(pcin, orig);
                lenprefix = ins - pcin;
                strncpy(pc, pcin, lenprefix);
                pc += lenprefix;
                strncpy(pc, replacement, lenrepl);
                pc += lenrepl;
                pcin += lenprefix + lenorig;
            }

            strncpy(pc, pcin, strlen(pcin));
            *(pc + strlen(pcin)) = '\0';
        }
        else
        {
            result = strdup(text);
        }
    }

    return result;
}

void base_strcasereplace_inplace(char **text, const char *orig, const char *repl)
{
    char *replacement = NULL;

    if (text)
    {
        replacement = base_strcasereplace(*text, orig, repl);

        if (replacement)
        {
            /* if replacement != NULL, then *text != NULL */
            free(*text);
            *text = replacement;
        }
    }
}

int convert_int_field(char *field, int len)
{
  char *buf;

  buf = alloca(len+1);
  memcpy(buf,field,len);
  return atoi(buf);
}

long convert_long_field(char *field, int len)
{
  char *buf;

  buf = alloca(len+1);
  memcpy(buf,field,len);
  return atol(buf);
}

float convert_float_field(char *field, int len)
{
  char *buf;

  buf = alloca(len+1);
  memcpy(buf,field,len);
  return (float)atof(buf);
}

double convert_double_field(char *field, int len)
{
  char *buf;

  buf = alloca(len+1);
  memcpy(buf,field,len);
  return atof(buf);
}


void convert_string_field(char *field, int len, char *output, int maxlen)
{
  int l;

  l = (len>maxlen?maxlen:len);
  strncpy(output,field,l);
  output[l] = '\0';
}


#define BUFSIZE (1<<20)

int copyfile(const char *inputfile, const char *outputfile)
{
  int fin, fout;
  ssize_t nread;
  char *buffer = 0;
  char *bufferorig = 0;
  int oflags;

#ifdef _GNU_SOURCE
  struct statvfs stat;
  static unsigned long align=-1;
  oflags = O_DIRECT;
#else
  oflags = 0;
#endif

  if ( (fin = open(inputfile, O_RDONLY|oflags) ) == -1 )
    return -1;

  if ( (fout = open(outputfile, O_WRONLY|O_CREAT|O_TRUNC|oflags, 0644 ) ) == -1
)
  {
    close(fin);
    return -2;
  }

#ifdef _GNU_SOURCE
  if (align == -1)
  {
    fstatvfs(fin, &stat);
    align = stat.f_bsize;
    fstatvfs(fout, &stat);
    align = align > stat.f_bsize ? align : stat.f_bsize;
  }

  bufferorig = malloc(BUFSIZE+align);
  XASSERT(bufferorig);
  buffer = bufferorig;
  buffer = buffer + (align - ((unsigned long)buffer % align));

#else
  buffer = malloc(BUFSIZE);
  XASSERT(buffer);
#endif


  while ( (nread = read(fin, buffer, BUFSIZE)) > 0 )
  {
    if ( write(fout, buffer, nread) < nread )
    {
      close(fin);
      close(fout);
      unlink(outputfile);

      if (bufferorig)
      {
         free(bufferorig);
      }

      return -3;
    }
  }
  close(fin);
  close(fout);

  if (bufferorig)
  {
     free(bufferorig);
  }

  if (nread == -1)
    return -4;
  else
    return 0;
}

static void FreeReservedDRMS(void *data)
{
   if (gReservedDRMS != (HContainer_t *)data)
   {
      fprintf(stderr, "Unexpected argument to FreeReservedDRMS(); bailing.\n");
      return;
   }

   hcon_destroy(&gReservedDRMS);
}

/*
<Keyword>
	= 'Keyword:' <KeyName> ',' <TypeAndFields>
<KeyName>
	= <Name>
<Name>
	= [A-Za-z_] { <NameEnd> }
<NameEnd>
	= [A-Za-z0-9_] { <NameEnd> }
*/

/* Returns 0 if drmsName is a valid DRMS keyword identifier, and not a reserved DRMS keyword name.
 * Returns 1 if drmsName is invalid
 * Returns 2 if drmsName is valid but reserved
 */
static int DRMSKeyNameValidationStatus(const char *drmsName)
{
   int error = 0;
   KwCharState_t state = kKwCharFirst;
   char *nameC = strdup(drmsName);
   char *pc = nameC;

   if (strlen(drmsName) > DRMS_MAXNAMELEN - 1)
   {
      error = 1;
   }
   else
   {
      /* Disallow PSQL reserved words */
      if (!gReservedDRMS)
      {
         char bogusval = 'A';
         int i = 0;

         gReservedDRMS = hcon_create(1, 128, NULL, NULL, NULL, NULL, 0);
         while (*(kKEYNAMERESERVED[i]) != '\0')
         {
            hcon_insert_lower(gReservedDRMS, kKEYNAMERESERVED[i], &bogusval);
            i++;
         }

         /* Register for clean up (also in the misc library) */
         BASE_Cleanup_t cu;
         cu.item = gReservedDRMS;
         cu.free = FreeReservedDRMS;
         base_cleanup_register("reserveddrmskws", &cu);
      }

      if (gReservedDRMS)
      {
         char *pch = NULL;
         if ((pch = strchr(nameC, '_')) != NULL)
         {
            /* there might be a reserved suffix */
            if (hcon_lookup_lower(gReservedDRMS, pch))
            {
               error = 2;
            }
         }
         else if (hcon_lookup_lower(gReservedDRMS, nameC))
         {
            error = 2;
         }
      }

      while (*pc != 0 && !error)
      {
	 switch (state)
	 {
	    case kKwCharError:
	      error = 1;
	      break;
	    case kKwCharFirst:
	      if (ISUPPER(*pc) ||
		  ISLOWER(*pc) ||
                  *pc == '_')
	      {
		 state = kKwCharNew;
		 pc++;
	      }
	      else
	      {
		 state = kKwCharError;
	      }
	      break;
	    case kKwCharNew:
	      if (ISUPPER(*pc) ||
		  ISLOWER(*pc) ||
		  ISDIGIT(*pc) ||
		  *pc == '_')
	      {
		 state = kKwCharNew;
		 pc++;
	      }
	      else
	      {
		 state = kKwCharError;
	      }
	      break;
	    default:
	      state = kKwCharError;
	 }
      }
   }

   if (nameC)
   {
      free(nameC);
   }

   return error;
}

/* DRMS name = ( [A-Z] | '_' ) ( [A-Z] | '_' | [0-9] )* */
int GenerateDRMSKeyName(const char *fitsName, char *drmsName, int size)
{
   int error = 0;
   const char *pcIn = fitsName;
   char *pcOut = drmsName;
   int fitsinvalid = 0;
   char *pch = NULL;

   KwCharState_t state = kKwCharFirst;

   while (*pcIn != 0 && pcOut < drmsName + size)
   {
      switch (state)
      {
         case kKwCharError:
           error = 1;
           break;

         case kKwCharFirst:
           if (*pcIn == '-')
           {
              /* FITS keyword name starts with an hyphen */
              if (pcOut + 2 <= drmsName + size)
              {
                 *pcOut++ = '_';
                 *pcOut++ = '_';
                 state = kKwCharNew;
                 fitsinvalid = 1;
              }
              else
              {
                 state = kKwCharError;
              }
           }
           else if (*pcIn >= 0x30 && *pcIn <= 0x39)
           {
              /* FITS keyword name starts with a numeral */
              if (pcOut + 2 <= drmsName + size)
              {
                 *pcOut++ = '_';
                 *pcOut++ = *pcIn;
                 state = kKwCharNew;
                 fitsinvalid = 1;
              }
              else
              {
                 state = kKwCharError;
              }
           }
           else
           {
              *pcOut++ = *pcIn;
              state = kKwCharNew;
           }

           break;
         case kKwCharNew:
           if (*pcIn == '-')
           {
              if (pcOut + 2 <= drmsName + size)
              {
                 *pcOut++ = '_';
                 *pcOut++ = '_';
                 state = kKwCharNew;
                 fitsinvalid = 1;
              }
              else
              {
                 state = kKwCharError;
              }
           }
           else
           {
              *pcOut++ = *pcIn;
              state = kKwCharNew;
           }
           break;

      } /* switch */

      if (state != kKwCharError)
      {
         pcIn++;
      }

   } /* while */

   *pcOut = '\0';

   /* if drmsName is a reserved DRMS keyword, then prepend with an underscore
    * because it must be valid otherwise */
   if (!error && DRMSKeyNameValidationStatus(drmsName) == 2)
   {
      /* but it could be reserved because of a suffix issue */
      char *tmp = strdup(drmsName);
      if (tmp && (pch = strchr(tmp, '_')) != NULL && hcon_lookup_lower(gReservedDRMS, pch))
      {
         *pch = '\0';
         snprintf(drmsName, size, "_%s", tmp);
      }
      else
      {
         snprintf(drmsName, size, "_%s", tmp);
      }

      fitsinvalid = 1;
      pcOut = drmsName + strlen(drmsName); /* point to terminating null */

      if (tmp)
      {
         free(tmp);
      }
   }


   if (fitsinvalid)
   {
      if (size - 1 < 9)
      {
         error = 1;
         fprintf(stderr, "Insufficient string buffer size '%d'.\n", size);
      }
      else
      {
         while (pcOut - drmsName < 9)
         {
            *pcOut++ = '_';
         }

         *pcOut = '\0';
      }
   }


   return !error;
}

#define kMAXRECURSION 128
int RemoveDir(const char *pathname, int maxrec)
{
   int status = 0;

   char pbuf[PATH_MAX];
   struct stat stBuf;

   if (maxrec < kMAXRECURSION && maxrec >= 0)
   {
      if (!stat(pathname, &stBuf) && S_ISDIR(stBuf.st_mode))
      {
         /* Append '/' if necessary */
         snprintf(pbuf, sizeof(pbuf), "%s", pathname);

         if (pathname[strlen(pathname) - 1] != '/')
         {
            base_strlcat(pbuf, "/", sizeof(pbuf));
         }

         struct dirent **fileList = NULL;
         int nFiles = -1;

         /* delete all non-dir files */
         if ((nFiles = scandir(pbuf, &fileList, NULL, NULL)) > 0 &&
             fileList != NULL)
         {
            int fileIndex = 0;

            while (fileIndex < nFiles)
            {
               struct dirent *entry = fileList[fileIndex];
               if (entry != NULL)
               {
                  char *oneFile = entry->d_name;
                  char dirEntry[PATH_MAX] = {0};
                  snprintf(dirEntry,
                           sizeof(dirEntry),
                           "%s%s",
                           pbuf,
                           oneFile);
                  if (*dirEntry !=  '\0' && !stat(dirEntry, &stBuf) && status == 0)
                  {
                     if (S_ISREG(stBuf.st_mode) || S_ISLNK(stBuf.st_mode))
                     {
                        /* delete single file */
                        status = unlink(dirEntry);
                     }
                     else if (S_ISDIR(stBuf.st_mode))
                     {
                        /* don't try to delete . or .. */
                        if (strcmp(oneFile, ".") != 0 && strcmp(oneFile, "..") != 0)
                        {
                           maxrec--;
                           if (maxrec >= 0)
                           {
                              status = RemoveDir(dirEntry, maxrec);
                           }
                        }
                     }
                  }

                  free(entry);
               }

               fileIndex++;
            }
         }

         /* delete the directory */
         if (status == 0)
         {
            status = rmdir(pathname);
         }
      }
   }

   return status;
}

/* On error, returns errno. */
size_t CopyFile(const char *src, const char *dst, int *ioerr)
{
   struct stat stbuf;
   FILE *fptrS = NULL;
   FILE *fptrD = NULL;
   char buf[2048];
   size_t nbytes = 0;
   size_t nbytesW = 0;
   size_t nbytesTotal = 0;
   int err = 0;

   if (!stat(src, &stbuf))
   {
      if (S_ISREG(stbuf.st_mode) || S_ISLNK(stbuf.st_mode))
      {
         fptrS = fopen(src, "r");

         if (!fptrS)
         {
            err = errno;
         }
         else
         {
            fptrD = fopen(dst, "w");

            if (!fptrD)
            {
               err = errno;
            }
         }

         if (fptrS && fptrD)
         {
            while (1)
            {
               nbytes = fread(buf, sizeof(char), sizeof(buf), fptrS);

               if (ferror(fptrS))
               {
                  fprintf(stderr, "CopyFile(): read-stream error indicator.\n");
                  break;
               }

               if (nbytes == 0)
               {
                  break;
               }

               nbytesW = fwrite(buf, sizeof(char), nbytes, fptrD);

               if (ferror(fptrD))
               {
                  fprintf(stderr, "CopyFile(): write-stream error indicator.\n");
                  break;
               }

               if (nbytesW != nbytes)
               {
                  fprintf(stderr, "CopyFile(): Failure writing all bytes.\n");
                  break;
               }

               nbytesTotal += nbytesW;
            }
         }

         if (fptrS)
         {
            fclose(fptrS);
         }

         if (fptrD)
         {
            fclose(fptrD);
         }
      }
       else if (S_ISDIR(stbuf.st_mode))
       {
           /* Recursively copy the files in the directory. */
           if (mkdir(dst, 0777))
           {
               fprintf(stderr, "Could not create output directory '%s'.\n", dst);
               err = 1;
           }
           else
           {
               int nfiles = 0;
               int ifile;
               struct dirent **fileList = NULL;
               struct dirent *entry = NULL;
               char srcFile[PATH_MAX];
               char dstFile[PATH_MAX];

               nfiles = scandir(src, &fileList, NULL, NULL);

               for (ifile = 0 ; ifile < nfiles; ifile++)
               {
                   entry = fileList[ifile];

                   if (entry != NULL)
                   {
                       char *oneFile = entry->d_name;

                       if (strcmp(oneFile, ".") != 0 && strcmp(oneFile, "..") != 0)
                       {
                           /* Recursive call. */
                           snprintf(srcFile, sizeof(srcFile), "%s/%s", src, oneFile);
                           snprintf(dstFile, sizeof(dstFile), "%s/%s", dst, oneFile);
                           nbytesW = CopyFile(srcFile, dstFile, ioerr);
                           nbytesTotal += nbytesW;
                       }

                       free(entry);
                       entry = NULL;
                   }
               }

               if (fileList)
               {
                   free(fileList);
                   fileList = NULL;
               }
           }
       }
   }
   else
   {
      err = errno;
   }

   if (ioerr)
   {
      *ioerr = err;
   }

   return nbytesTotal;
}

void base_cleanup_init()
{
   gCleanup = hcon_create(sizeof(BASE_Cleanup_t), 128, NULL, NULL, NULL, NULL, 0);
}

int base_cleanup_register(const char *key, BASE_Cleanup_t *cu)
{
   int error = 0;

   if (!gCleanup)
   {
      base_cleanup_init();
   }

   if (gCleanup)
   {
      if (hcon_lookup(gCleanup, key))
      {
         /* already exists */
         fprintf(stderr, "base_cleanup_register(): cannot register '%s' - already exists.\n", key);
         error = 1;
      }
      else
      {
         hcon_insert(gCleanup, key, cu);
      }
   }

   return error;
}

int base_cleanup_go(const char *explicit)
{
    int error = 0;
    BASE_Cleanup_t *cu = NULL;

    if (gCleanup)
    {
        if (explicit && *explicit)
        {
            cu = hcon_lookup(gCleanup, explicit);

            if (cu)
            {
                (*(cu->free))(cu->item);
                hcon_remove(gCleanup, explicit);
            }
            else
            {
                error = 1;
            }
        }
        else
        {
            /* clean all up */
            HIterator_t *hiter = hiter_create(gCleanup);
            const char *keyname = NULL;
            char **toRemove = NULL;
            int ielem;
            int ntotal;

            ntotal = gCleanup->num_total;

            if (gCleanup && ntotal > 0)
            {
                toRemove = calloc(gCleanup->num_total, sizeof(char *));
            }

            if (toRemove)
            {
                ielem = 0;
                while ((cu = hiter_extgetnext(hiter, &keyname)) != NULL)
                {
                    (*(cu->free))(cu->item);
                    /* I think I can do this - remove one while iterating
                     * no you can't. */
                    /* hcon_remove(gCleanup, keyname); */
                    toRemove[ielem] = strdup(keyname);
                    if (!toRemove[ielem])
                    {
                        fprintf(stderr, "Out of memory in base_cleanup_go().\n");
                        error = 1;
                        break;
                    }

                    ielem++;
                }

                for (ielem = 0; ielem < ntotal; ielem++)
                {
                    if (toRemove[ielem])
                    {
                        hcon_remove(gCleanup, toRemove[ielem]);
                        free(toRemove[ielem]);
                        toRemove[ielem] = NULL;
                    }
                }

                free(toRemove);
                toRemove = NULL;
            }
            else
            {
                fprintf(stderr, "Out of memory in base_cleanup_go().\n");
                error = 1;
            }

            hiter_destroy(&hiter);
        }
    }

    return error;
}

void base_cleanup_term()
{
   if (gCleanup)
   {
      hcon_destroy(&gCleanup);
   }
}

void base_term()
{
   base_cleanup_go(NULL);
   base_cleanup_term();
}

int base_drmskeycheck(const char *drmsName)
{
   return DRMSKeyNameValidationStatus(drmsName);
}

int base_isvers(const char *vers, const char *minvers)
{
    long long major;
    long long minor;
    long long minmajor;
    long long minminor;

    int ok = 1;

    if (*vers == '\0')
    {
        ok = 0;
    }
    else if (sscanf(vers, "%lld.%lld", &major, &minor) == 2)
    {
        if (*minvers != '\0')
        {
            /* Series must be GTE to first */
            if (sscanf(minvers, "%lld.%lld", &minmajor, &minminor) == 2)
            {
                if (major < minmajor || (major == minmajor && minor < minminor))
                {
                    ok = 0;
                }
            }
            else
            {
                fprintf(stderr, "Invalid version string '%s'.\n", minvers);
                ok = 0;
            }
        }
    }
    else
    {
        fprintf(stderr, "Invalid version string '%s'.\n", vers);
        ok = 0;
    }

    return ok;
}

int base_floatIsEqual(const float val1, const float val2)
{
    union
    {
        int32_t integer;
        float singlePrecFP;
    } conv1, conv2;

    conv1.singlePrecFP = val1;
    conv2.singlePrecFP = val2;

    return (conv1.integer == conv2.integer);
}

int base_doubleIsEqual(const double val1, const double val2)
{
    union
    {
        int64_t integer;
        double doublePrecFP;
    } conv1, conv2;

    conv1.doublePrecFP = val1;
    conv2.doublePrecFP = val2;

    return (conv1.integer == conv2.integer);
}

int base_nsAndTab(const char *name, char **ns, char **tab)
{
    int err = 0;
    char *nspace = strdup(name);
    char *pc = strrchr(nspace, '.');

    if (pc)
    {
        *pc = '\0';
    }
    else
    {
        err = 1;
    }

    if (!err)
    {
        *ns = nspace;
        *tab = strdup(++pc);
    }

    return err;
}

/* strip leading and trailing whitespace */
int base_strip_whitespace(const char *string_in, char **string_out)
{
    int err = 0;
    static regex_t *reg_expression = NULL;
    const char *pattern = "^[[:space:]]*([[:print:]]*[[:alnum:][:punct:]])[[:space:]]*$";
    regmatch_t matches[2]; /* index 0 is the entire string */

    if (!reg_expression)
    {
        /* ART - not going to bother freeing this! */
        reg_expression = calloc(1, sizeof(regex_t));
        if (regcomp(reg_expression, pattern, REG_EXTENDED) != 0)
        {
            err = 1;
        }
    }

    if (!err)
    {
        if (regexec(reg_expression, string_in, sizeof(matches) / sizeof(matches[0]), matches, 0) == 0)
        {
            if (matches[1].rm_so != -1)
            {
                *string_out = calloc(matches[1].rm_eo - matches[1].rm_so + 1, sizeof(char));
                memcpy(*string_out, string_in + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
            }
        }
        else
        {
            /* no match, or failure */
            if (*string_in == '\0')
            {
                *string_out = strdup(string_in);
            }
            else
            {
                *string_out = NULL;
                err = 1;
            }
        }
    }

    return err;
}
