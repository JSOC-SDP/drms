/*
    This module always sends FITS file to its stdout stream. The actual file stream that the FITS-file bytes are sent
    can be controlled by redirecting stdout. If using the Python subprocess module, the caller can supply the stdout
    argument to various subprocess functions to redirect child-process output to a different stream (such as a disk file
    or a pipe).
 */

/* The caller will take care of the HTML headers, if this module is run in a cgi or web context. The header looks like:
 *   Content-type: application/octet-stream
 *   Content-Disposition: attachment; filename="tarfilename.tar"
 *   Content-transfer-encoding: binary
 */

 /* The original drms_export_cgi had a method argument (STAGE_CGI) that caused FITS files or tar files of FITS files
  * to be saved to a local path; this module ONLY writes to stdout; the STAGE_CGI feature of drms_export_cgi
  * was not used - should we need that feature, the caller of this module can redirect to a local file.
  */
#include <pwd.h>
#include <grp.h>
#include "json.h"
#include "jsoc_main.h"
#include "exputil.h"
/* enable the ability to pass in FITS structures to the fitsexport - could put this in make instead if desired */
#define USE_FITS_STRUCTS 1
#include "fitsexport.h"
#undef USE_FITS_STRUCTS

/* third-party stuff */
#include "fitsio.h"

char *module_name = "drms-export-to-stdout";

#define ARG_RS_SPEC "spec"
#define ARG_KEYMAP_CLASS "mapclass"
#define ARG_KEYMAP_FILE "mapfile"
#define ARG_FILE_TEMPLATE "ffmt"
#define ARG_CPARMS_STRING "cparms"
#define ARG_ACK_FILE "ackfile"
#define ARG_MAX_TAR_FILE_SIZE "maxfilesize"
#define ARG_COMPRESS_ALL_SEGS "a" /* if set, then apply a single CPARMS value to all segments */
#define ARG_DO_NOT_CREATE_TAR "s" /* if there is more than one FITS file requested in spec, error out */
#define ARG_DUMP_FILE_NAME "d" /* if not making a tar, then dump the name of the FITS file at the beginning of the stream */
#define ARG_SUPPRESS_STDERR "e" /* if set, then do not print error messages and warnings to stderr */

#define FILE_LIST_PATH "jsoc/file_list.json"
#define ERROR_LIST_PATH "jsoc/error_list.json"
#define ERROR_PATH "jsoc/error.txt"

#define DEFAULT_MAX_TAR_FILE_SIZE "4294967296" /* 4 GB*/
#define MAX_MAX_TAR_FILE_SIZE 53687091200 /* 50 GB - the maxfilesize argument cannot be larger than this */
#define TAR_BLOCK_SIZE 512
#define TAR_HEADER_SIZE 512
#define ACK_FILE_BUFFER 96
#define FILE_NAME_SIZE 256 /* the size of the buffer for the name of the file exported */

/* status codes */
enum __ExpToStdoutStatus_enum__
{
    ExpToStdoutStatus_Success = 0,
    ExpToStdoutStatus_InvalidArgs = 1,
    ExpToStdoutStatus_Dump = 2,
    ExpToStdoutStatus_OutOfMemory = 3,
    ExpToStdoutStatus_DumpPadding = 4,
    ExpToStdoutStatus_GetUser = 5,
    ExpToStdoutStatus_GetGroup = 6,
    ExpToStdoutStatus_IO = 7,
    ExpToStdoutStatus_BadFilenameTemplate = 8,
    ExpToStdoutStatus_DRMS = 9,
    ExpToStdoutStatus_Stdout = 10,
    ExpToStdoutStatus_TarTooLarge = 11,
    ExpToStdoutStatus_AllExportsFailed = 12,
    ExpToStdoutStatus_MoreThanOneFileToExport = 13,
    ExpToStdoutStatus_CantDumpFileNameForTarFile = 14
};

typedef enum __ExpToStdoutStatus_enum__ ExpToStdoutStatus_t;

/* compression strings */
#define COMPRESSION_NONE "none"
#define COMPRESSION_RICE "rice"
#define COMPRESSION_GZIP1 "gzip1"
#define COMPRESSION_GZIP2 "gzip2"
#define COMPRESSION_PLIO "plio"
#define COMPRESSION_HCOMP "hcompress"

/* compression enum */
enum __ExpToStdout_Compression_enum__
{
    ExpToStdout_Compression_NONE = 0,
    ExpToStdout_Compression_RICE = RICE_1,
    ExpToStdout_Compression_GZIP1 = GZIP_1,
#if CFITSIO_MAJOR >= 4 || (CFITSIO_MAJOR == 3 && CFITSIO_MINOR >= 27)
    ExpToStdout_Compression_GZIP2 = GZIP_2,
#endif
    ExpToStdout_Compression_PLIO = PLIO_1,
    ExpToStdout_Compression_HCOMP = HCOMPRESS_1
};

typedef enum __ExpToStdout_Compression_enum__ ExpToStdout_Compression_t;

ModuleArgs_t module_args[] =
{
    { ARG_STRING, ARG_RS_SPEC, NULL, "record-set query that specifies data to be exported" },
    { ARG_STRING, ARG_KEYMAP_CLASS, " ", "export key-map class" },
    { ARG_STRING, ARG_KEYMAP_FILE, " ", "export key-map file" },
    { ARG_STRING, ARG_FILE_TEMPLATE, " ", "export FITS filename template" },
    { ARG_STRINGS, ARG_CPARMS_STRING, " ", "a list of FITSIO compression types (none, rice, gzip1, gzip2, plio, hcompress), one for each segment; default is rice for all segments" },
    { ARG_STRING, ARG_ACK_FILE, " ", "a file provided by the caller to include in the tar file"},
    { ARG_INT, ARG_MAX_TAR_FILE_SIZE, DEFAULT_MAX_TAR_FILE_SIZE, "the maximum size in bytes of the resulting tar file"},
    { ARG_FLAG, ARG_COMPRESS_ALL_SEGS, NULL, "apply the single string in ARG_CPARMS_STRING to all segments" },
    { ARG_FLAG, ARG_DO_NOT_CREATE_TAR, NULL, "skip producing a tar file if a single FITS file is being exported" },
    { ARG_FLAG, ARG_DUMP_FILE_NAME, NULL, "dump the name of the FITS file at the beginning of the stream"},
    { ARG_FLAG, ARG_SUPPRESS_STDERR, NULL, "do not print error messages to stdout (if not making a tar file)"},
    { ARG_END }
};

static void GetOptionValue(ModuleArgs_Type_t type, const char *key, void *result)
{
    switch (type)
    {
        case ARG_STRING:
        {
            const char *innards = NULL;

            innards = params_get_str(&cmdparams, (char *)key); /* stupid cmdparams does not make this parameter const */
            if (strcmp(innards, " "))
            {
                *(const char **)result = innards;
            }
        }
        break;
        case ARG_STRINGS:
        {
            char **strings = NULL;
            int nElems = 0;
            LinkedList_t *list = NULL;
            int iElem;

            nElems = cmdparams_get_strarr(&cmdparams, (char *)key, &strings, NULL); /* stupid cmdparams does not make this parameter const */

            if (nElems != 0 && (nElems != 1 || strcmp(strings[0], " ")))
            {
                list = list_llcreate(sizeof(char *), NULL);
                if (list)
                {
                    for (iElem = 0; iElem < nElems; iElem++)
                    {
                        list_llinserttail(list, strings[iElem]);
                    }

                    *(LinkedList_t **)result = list;
                }
            }
        }
        break;
        case ARG_INT:
        {
            long long intVal = 0;

            intVal = params_get_int64(&cmdparams, (char *)key);
            *(long long *)result = intVal;
        }
        break;
        case ARG_FLAG:
        {
            int flag = 0;

            flag = cmdparams_isflagset(&cmdparams, (char *)key);
            *(int *)result = flag;
        }
        break;
    }
}

/* outBuf is dynamically allocated; outSize is the current size of allocation */
static ExpToStdoutStatus_t Dump(FILE *stream, const char *buf, size_t numBytes, size_t *numBytesDumped)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    size_t numDumped = 0;

    if (stream)
    {
        numDumped = fwrite(buf, 1, numBytes, stream);
        if (numDumped != numBytes)
        {
            fprintf(stderr, "unable to dump to stream\n");
            expStatus = ExpToStdoutStatus_Dump;
        }
    }
    else
    {
        fprintf(stderr, "Dump(): invalid arguments\n");
    }

    if (numBytesDumped)
    {
        if (expStatus == ExpToStdoutStatus_Success)
        {
            *numBytesDumped = *numBytesDumped + numDumped;
        }
        else
        {
            *numBytesDumped = *numBytesDumped + 0;
        }
    }

    return expStatus;
}

static ExpToStdoutStatus_t DumpPadding(FILE *stream, size_t existing, size_t total, size_t *numBytesDumped)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    size_t numDumped = 0;

    if (total > existing)
    {
        char *buf = NULL;

        buf = calloc(total - existing, 1);
        if (buf)
        {
            expStatus = Dump(stream, buf, total - existing, &numDumped);
            free(buf);
        }
        else
        {
            expStatus = ExpToStdoutStatus_OutOfMemory;
        }
    }
    else if (total < existing)
    {
        fprintf(stderr, "cannot pad to %lu bytes when %lu bytes have already been written\n", total, existing);
        expStatus = ExpToStdoutStatus_DumpPadding;
    }

    if (numBytesDumped)
    {
        if (expStatus == ExpToStdoutStatus_Success)
        {
            *numBytesDumped = *numBytesDumped + numDumped;
        }
        else
        {
            *numBytesDumped = *numBytesDumped + 0;
        }
    }

    return expStatus;
}

static ExpToStdoutStatus_t DumpAndPad(FILE *stream, const char *buf, size_t numBytes, size_t total, size_t *numBytesDumped)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    size_t numDumped = 0;

    if (total >= numBytes)
    {
        expStatus = Dump(stream, buf, numBytes, &numDumped);
        if (expStatus == ExpToStdoutStatus_Success)
        {
            expStatus = DumpPadding(stream, numBytes, total, &numDumped);
        }
    }

    if (numBytesDumped)
    {
        if (expStatus == ExpToStdoutStatus_Success)
        {
            *numBytesDumped = *numBytesDumped + numDumped;
        }
        else
        {
            *numBytesDumped = *numBytesDumped + 0;
        }
    }

    return expStatus;
}

static ExpToStdoutStatus_t DumpOctal(FILE *stream, long long value, size_t fieldWidth, size_t *numBytesDumped)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    size_t numDumped = 0;

    char *field = NULL;

    field = calloc(1, fieldWidth + 1);
    if (field)
    {
        snprintf(field, fieldWidth + 1, "%0*llo\0", (int)fieldWidth - 1, value); /* trailing NUL ('\0') char */
        expStatus = Dump(stream, field, fieldWidth, &numDumped);
    }

    if (numBytesDumped)
    {
        if (expStatus == ExpToStdoutStatus_Success)
        {
            *numBytesDumped = *numBytesDumped + numDumped;
        }
        else
        {
            *numBytesDumped = *numBytesDumped + 0;
        }
    }

    return expStatus;
}

/* header must consist of all ascii chars */
static ExpToStdoutStatus_t DumpTarFileObjectHeader(FILE *stream, const char *fileName, size_t fileSize)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;

    struct passwd pwd;
    struct passwd *resultPwd = NULL;
    struct group grp;
    struct group *resultGrp = NULL;
    uid_t uid;
    gid_t gid;
    char *idBuf = NULL;
    size_t idBufSize;
    int pipefds[2];  /* stupid checksum - we cannot dump bytes on stdout in one pass */
    char header[TAR_HEADER_SIZE];
    FILE *writeStream = NULL;
    FILE *readStream = NULL;
    unsigned long long chksum = 0;
    size_t numBytesDumped = 0;

    if (pipe(pipefds))
    {
        expStatus = ExpToStdoutStatus_IO;
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* open write end */
        writeStream = fdopen(pipefds[1], "w");
        if (!writeStream)
        {
            expStatus = ExpToStdoutStatus_IO;
        }
        else
        {
            /* open read end */
            readStream = fdopen(pipefds[0], "r");
            if (!readStream)
            {
                expStatus = ExpToStdoutStatus_IO;
            }
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* file name - left-justified string will all trailing '\0' bytes */
        expStatus = DumpAndPad(writeStream, fileName, strlen(fileName), 100, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* file mode - octal */
        expStatus = DumpOctal(writeStream, 436, 8, NULL); /* O0664 */
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* uid - octal */
        idBufSize = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);

        if (idBufSize == -1)
        {
            idBufSize = 16384;
        }

        idBuf = malloc(idBufSize);
        if (!idBuf )
        {
            expStatus = ExpToStdoutStatus_OutOfMemory;
        }
        else
        {
            uid = getuid();
            getpwuid_r(uid, &pwd, idBuf, idBufSize, &resultPwd);

            if (!resultPwd)
            {
                /* not found or failure */
                fprintf(stderr, "user id %u not found\n", uid);
                expStatus = ExpToStdoutStatus_GetUser;
            }
        }

        expStatus = DumpOctal(writeStream, pwd.pw_uid, 8, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* gid - octal */
        gid = pwd.pw_gid;
        expStatus = DumpOctal(writeStream, gid, 8, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* size - octal */
        expStatus = DumpOctal(writeStream, fileSize, 12, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* mtime - octal */
        expStatus = DumpOctal(writeStream, time(NULL), 12, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* chksum - sum of unsigned byte values of all other fields in header */

        /* for now, pretend that the checksum is 8 spaces, because the spec says
         * to set this field to all spaces when calculating the checksum
         */
         expStatus = Dump(writeStream, "        ", 8, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* file type (regular) */
        expStatus = DumpOctal(writeStream, 0, 1, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* linkname - string (unused) */
        expStatus = DumpPadding(writeStream, 0, 100, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* magic - "ustar" */
        expStatus = DumpAndPad(writeStream, "ustar", 5, 6, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* version - "00" with NO terminating NUL char */
        expStatus = DumpAndPad(writeStream, "00", 2, 2, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* uname */
        expStatus = DumpAndPad(writeStream, pwd.pw_name, strlen(pwd.pw_name), 32, NULL);

        /* no longer need pwd - we need gid, but we copied that already */
        if (idBuf)
        {
            free(idBuf);
            idBuf = NULL;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* gname */

        /* sigh */
        idBufSize = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX);

        if (idBufSize == -1)
        {
            idBufSize = 16384;
        }

        idBuf = malloc(idBufSize);
        if (!idBuf)
        {
            expStatus = ExpToStdoutStatus_OutOfMemory;
        }
        else
        {
            getgrgid_r(gid, &grp, idBuf, idBufSize, &resultGrp);

            if (!resultGrp)
            {
                /* not found or failure */
                fprintf(stderr, "group id %u not found\n", gid);
                expStatus = ExpToStdoutStatus_GetGroup;
            }
            else
            {
                expStatus = DumpAndPad(writeStream, grp.gr_name, strlen(grp.gr_name), 32, NULL);
            }
        }

        /* no longer need grp */
        if (idBuf)
        {
            free(idBuf);
            idBuf = NULL;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* device major */
        expStatus = DumpPadding(writeStream, 0, 8, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* device minor */
        expStatus = DumpPadding(writeStream, 0, 8, NULL);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* prefix - path to file (just a base name) */
        expStatus = DumpPadding(writeStream, 0, 155, NULL);
    }

    /* now we have to read back the header */
    if (expStatus == ExpToStdoutStatus_Success)
    {
        char *ptr = NULL;
        size_t num = 0;

        /* flush, close the write-end of the pipe */
        fflush(writeStream);
        fclose(writeStream);
        close(pipefds[1]); /* necessary so that reading from the read end does not block */

        /* read the read end of the pipe */
        memset(header, 0, sizeof(header));
        ptr = header;
        while (1)
        {
            num = fread(ptr, sizeof(char), TAR_HEADER_SIZE - num, readStream);
            if (num <= 0)
            {
                break;
            }
            else
            {
                ptr += num;
            }
        }

        fclose(readStream);
        close(pipefds[0]);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        char *ptr;

        /* calculate the checksum */
        ptr = header;
        while (ptr < header + sizeof(header))
        {
            chksum += (int)*ptr;
            ptr++;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* now dump all the bytes before the checksum */
        numBytesDumped = 0;
        expStatus = Dump(stream, header, 148, &numBytesDumped);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* dump the checksum - dump 6 octal numbers, followed by NUL, ...*/
        expStatus = DumpOctal(stream, chksum, 7, &numBytesDumped);

        /* and then followed by a space char */
        if (expStatus == ExpToStdoutStatus_Success)
        {
            expStatus = Dump(stream, " ", 1, &numBytesDumped);
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* finally, dump the rest */
        expStatus = Dump(stream, &header[numBytesDumped], sizeof(header) - numBytesDumped, &numBytesDumped);
    }

    /* on error, this might not have gotten cleaned up */
    if (idBuf)
    {
        free(idBuf);
        idBuf = NULL;
    }

    return expStatus;
}

static ExpToStdoutStatus_t FillBlock(FILE *stream, int blockSize, int writeSize)
{
    int remainder = writeSize % blockSize;

    if (remainder != 0)
    {
        return DumpPadding(stream, 0, blockSize - remainder, NULL);
    }

    return ExpToStdoutStatus_Success;
}

/* filePath - path of the file to be stored in the TAR file
 * buffer - file data
 * size - number of bytes of file data
 */
static ExpToStdoutStatus_t WriteFileBuffer(FILE *stream, const char *filePath, const char *buffer, size_t size)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;

    /* dump TAR header */
    expStatus = DumpTarFileObjectHeader(stream, filePath, size);

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* dump buffer */
        fprintf(stream, buffer);

        /* pad - fill up last 512 block with zeroes */
        expStatus = FillBlock(stream, TAR_BLOCK_SIZE, size);
    }

    fflush(stream);

    return expStatus;
}

static ExpToStdoutStatus_t WriteFile(FILE *writeStream, const char *filePath, size_t bufSize)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    const char *baseName = NULL;
    struct stat stBuf;
    char *readBuffer = NULL;
    size_t numBytesRead;
    char *ptr = NULL;
    FILE *readStream = NULL;


    if (lstat(filePath, &stBuf) != 0)
    {
        fprintf(stderr, "cannot get %s file status\n", filePath);
        expStatus = ExpToStdoutStatus_IO;
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* dump TAR header */
        baseName = strrchr(filePath, '/');
        baseName = baseName ? baseName + 1 : filePath;
        expStatus = DumpTarFileObjectHeader(writeStream, baseName, stBuf.st_size);
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        readStream = fopen(filePath, "r");
        if (readStream == NULL)
        {
            fprintf(stderr, "cannot open file %s for reading\n", filePath);
            expStatus = ExpToStdoutStatus_IO;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        readBuffer = calloc(sizeof(char), bufSize);
        if (!readBuffer)
        {
            expStatus = ExpToStdoutStatus_OutOfMemory;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* read file contents */
        while (1)
        {
            numBytesRead = fread(readBuffer, sizeof(char), bufSize - 1, readStream);
            if (numBytesRead <= 0)
            {
                break;
            }
            else
            {
                readBuffer[numBytesRead] = '\0';
                fprintf(writeStream, readBuffer);
            }
        }

        free(readBuffer);
        readBuffer = NULL;

        fclose(readStream);
        readStream = NULL;
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* pad - fill up last 512 block with zeroes */
        expStatus = FillBlock(writeStream, TAR_BLOCK_SIZE, stBuf.st_size);
    }

    fflush(writeStream);

    return expStatus;
}

static ExpToStdoutStatus_t WriteAckFile(FILE *writeStream, const char *path)
{
    return WriteFile(writeStream, path, ACK_FILE_BUFFER);
}

static ExpToStdoutStatus_t DropDataOnFloor(fitsfile *fitsPtr)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    long long numBytesFitsFile = fitsPtr->Fptr->logfilesize;
    int savedStdout = -1;
    char fileBuf[4096];
    int num;
    int fiostat = 0;
    int devnull = -1;

    if (numBytesFitsFile > 0)
    {
        /* open /dev/null */
        devnull = open("/dev/null", O_WRONLY);

        if (devnull == -1)
        {
            fprintf(stderr, "unable to open /dev/null for writing\n");
            expStatus = ExpToStdoutStatus_IO;
        }

        if (expStatus == ExpToStdoutStatus_Success)
        {
            savedStdout = dup(STDOUT_FILENO);
            if (savedStdout != -1)
            {
                if (dup2(devnull, STDOUT_FILENO) != -1)
                {
                    fiostat = 0;
                    fits_close_file(fitsPtr, &fiostat);
                    if (fiostat)
                    {
                        fprintf(stderr, "unable to close and send FITS file\n");
                    }

                    fflush(stdout);
                }
                else
                {
                    /* can't flush FITSIO internal buffers */
                    fprintf(stderr, "unable to flush FITSIO internal buffers following error\n");
                }

                /* restore stdout */
                dup2(savedStdout, STDOUT_FILENO);
                close(savedStdout);
            }
            else
            {
                /* can't flush FITSIO internal buffers */
                fprintf(stderr, "unable to flush FITSIO internal buffers following error\n");
            }

            close(devnull);
        }
    }

    return expStatus;
}

static ExpToStdoutStatus_t Capture_stderr(int saved_pipes[2], int *saved_stderr, FILE **read_stream)
{
    ExpToStdoutStatus_t exp_status = ExpToStdoutStatus_Success;
    int pipe_fds[2] = {-1, -1};
    int saved = -1;
    FILE *stream = NULL;


    if (pipe(pipe_fds) == -1)
    {
        exp_status = ExpToStdoutStatus_IO;
    }

    if (exp_status == ExpToStdoutStatus_Success)
    {
        saved = dup(STDERR_FILENO);

        if (saved != -1)
        {
            if (dup2(pipe_fds[1], STDERR_FILENO) != -1)
            {
                /* open read-end stream */
                stream = fdopen(pipe_fds[0], "r");
                if (!stream)
                {
                    /* restore stderr */
                    dup2(saved, STDERR_FILENO);
                    exp_status = ExpToStdoutStatus_IO;
                }
            }
            else
            {
                exp_status = ExpToStdoutStatus_IO;
            }
        }
        else
        {
            exp_status = ExpToStdoutStatus_IO;
        }
    }

    if (exp_status == ExpToStdoutStatus_Success)
    {
        saved_pipes[0] = pipe_fds[0];
        saved_pipes[1] = pipe_fds[1];
        *saved_stderr = saved;
        *read_stream = stream;
    }
    else
    {
        if (stream)
        {
            fclose(stream);
        }

        if (saved != -1)
        {
            close(saved);
        }

        if (pipe_fds[0] != -1)
        {
            close(pipe_fds[0]);
        }

        if (pipe_fds[1] != -1)
        {
            close(pipe_fds[1]);
        }
    }

    return exp_status;
}

static int Restore_stderr(int saved_pipes[2], int *saved_stderr, FILE **stream, char **buffer_out)
{
    ExpToStdoutStatus_t exp_status = ExpToStdoutStatus_Success;
    char buffer[1025] = {0};
    size_t num_bytes = 0;
    size_t sz_buffer_out = 2048;


    *buffer_out = calloc(1, sz_buffer_out);

     /* necessary to close write-end of pipe so that reading from the read end does not block; and
      * to close write-end of pipe, we need to first restore stderr (make STDERR_FILENO point back to whatever
      * STDERR_FILENO was pointing to - probably tty - before redirection) */
    if (dup2(*saved_stderr, STDERR_FILENO) == -1)
    {
        exp_status = ExpToStdoutStatus_IO;
    }

    close(*saved_stderr);
    *saved_stderr = -1;

    if (close(saved_pipes[1]) == -1)
    {
        exp_status = ExpToStdoutStatus_IO;
    }

    saved_pipes[1] = -1;

    if (exp_status == ExpToStdoutStatus_Success)
    {
        /* read the read end of the pipe */
        while (1)
        {
            memset(buffer, '\0', sizeof(buffer));
            num_bytes = fread(buffer, sizeof(char), sizeof(buffer) - 1, *stream);
            if (num_bytes <= 0)
            {
                break;
            }
            else
            {
                *buffer_out = base_strcatalloc(*buffer_out, buffer, &sz_buffer_out);
            }
        }
    }

    /* close read stream */
    fclose(*stream);
    *stream = NULL;

    /* close read pipe */
    close(saved_pipes[0]);
    saved_pipes[0] = -1;

    return exp_status;
}


/* loop over segments */
/* segCompression is an array of FITSIO macros, one for each segment, that specify the type of compression to perform; if NULL, then compress all segments with Rice compression
 */
static ExpToStdoutStatus_t ExportRecordToStdout(int makeTar, int dumpFileName, int suppress_stderr, DRMS_Record_t *expRec, const char *ffmt, ExpToStdout_Compression_t *segCompression, int compressAllSegs, const char *classname, const char *mapfile, size_t *bytesExported, size_t maxTarFileSize, size_t *numFilesExported, json_t *infoDataArr, json_t *errorDataArr)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    int drmsStatus = DRMS_SUCCESS;
    int fiostat = 0;
    char recordSpec[DRMS_MAXQUERYLEN];
    DRMS_Segment_t *segIn = NULL;
    int iSeg;
    HIterator_t *last = NULL;
    DRMS_Segment_t *segTgt = NULL; /* If segin is a linked segment, then tgtset is the segment in the target series. */
    char formattedFitsName[DRMS_MAXPATHLEN];
    ExpUtlStat_t expUStat = kExpUtlStat_Success;
    fitsfile *fitsPtr = NULL;
    long long numBytesFitsFile; /* the actual FITSIO type is LONGLONG */
    size_t totalBytes = 0;
    size_t totalFiles = 0;
    json_t *recobj = NULL;
    int saved_pipes[2] = {-1, -1};
    int saved_stderr = -1;
    char *captured_stderr = NULL;
    FILE *read_stream = NULL;
    char specbuf[1024];
    char msg[256];
    char errMsg[512];

    drms_sprint_rec_query(recordSpec, expRec);

    iSeg = 0;
    while ((segIn = drms_record_nextseg(expRec, &last, 0)) != NULL)
    {
        if (segIn->info->islink)
        {
            if ((segTgt = drms_segment_lookup(expRec, segIn->info->name)) == NULL)
            {
                snprintf(msg, sizeof(msg), "unable to locate linked segment file %s", segIn->info->name);

                if (!suppress_stderr)
                {
                    fprintf(stderr, msg);
                    fprintf(stderr, "\n");
                }

                if (makeTar && errorDataArr)
                {
                    recobj = json_new_object();
                    snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                    json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                    json_insert_pair_into_object(recobj, "segment", json_new_string(segIn->info->name));
                    json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                    json_insert_child(errorDataArr, recobj);
                }

                iSeg++;
                continue;
            }
        }
        else
        {
            segTgt = segIn;
        }

        if ((expUStat = exputl_mk_expfilename(segIn, segTgt, ffmt, formattedFitsName)) != kExpUtlStat_Success)
        {
            if (expUStat == kExpUtlStat_InvalidFmt)
            {
                snprintf(msg, sizeof(msg), "invalid file-name format template %s", ffmt);
            }
            else if (expUStat == kExpUtlStat_UnknownKey)
            {
                snprintf(msg, sizeof(msg), "one or more keywords in the file-name-format template %s do not exist in series %s", ffmt, expRec->seriesinfo->seriesname);
            }
            else
            {
                snprintf(msg, sizeof(msg), "unable to resolve file-name template %s", ffmt);
            }

            if (!suppress_stderr)
            {
                fprintf(stderr, msg);
                fprintf(stderr, "\n");
            }

            if (makeTar && errorDataArr)
            {
                recobj = json_new_object();
                snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                json_insert_pair_into_object(recobj, "segment", json_new_string(segIn->info->name));
                json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                json_insert_child(errorDataArr, recobj);
            }

            expStatus = ExpToStdoutStatus_BadFilenameTemplate;
            break;
        }

        fiostat = 0;
        if (fits_create_file(&fitsPtr, "-", &fiostat))
        {
            fits_report_error(stderr, fiostat);
            snprintf(msg, sizeof(msg), "cannot create FITS file");

            if (!suppress_stderr)
            {
                fprintf(stderr, msg);
                fprintf(stderr, "\n");
            }

            if (makeTar && errorDataArr)
            {
                recobj = json_new_object();
                snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                json_insert_child(errorDataArr, recobj);
            }

            iSeg++;
            continue; /* we've logged an error message now go onto the next segment; do not set status to error */
        }

        /* set compression, if requested */
        fiostat = 0;
        if (segCompression)
        {
            if (compressAllSegs && (segCompression[0] != ExpToStdout_Compression_NONE))
            {
                fits_set_compression_type(fitsPtr, segCompression[0], &fiostat);
            }
            else if (segCompression[iSeg] && segCompression[iSeg] != ExpToStdout_Compression_NONE)
            {
                fits_set_compression_type(fitsPtr, segCompression[iSeg], &fiostat);
            }
        }
        else
        {
            fits_set_compression_type(fitsPtr, ExpToStdout_Compression_RICE, &fiostat);
        }

        if (fiostat)
        {
            fits_report_error(stderr, fiostat);
            /* close the fitsfile * - there should be no data written to stdout */
            fits_close_file(fitsPtr, &fiostat);

            snprintf(msg, sizeof(msg), "unable to set FITS compression");

            if (!suppress_stderr)
            {
                fprintf(stderr, msg);
                fprintf(stderr, "\n");
            }

            if (makeTar && errorDataArr)
            {
                recobj = json_new_object();
                snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                json_insert_child(errorDataArr, recobj);
            }

            iSeg++;
            continue;
        }

        if (suppress_stderr)
        {
            /* capture any stderr and create a recobj from it; read_stream will contain stderr */
            expStatus = Capture_stderr(saved_pipes, &saved_stderr, &read_stream);
        }

        if (expStatus == ExpToStdoutStatus_Success)
        {
            /* writes FITS file to write end of pipe (by re-directing stdout to the pipe) */
            drmsStatus = fitsexport_mapexport_tostdout(fitsPtr, segIn, classname, mapfile);

            if (suppress_stderr)
            {
                /* put captured stderr into buffer */
                expStatus = Restore_stderr(saved_pipes, &saved_stderr, &read_stream, &captured_stderr);

                if (expStatus == ExpToStdoutStatus_Success)
                {
                    if (makeTar)
                    {
                        /* successfully read from stderr - make a recobj */
                        recobj = json_new_object();
                        snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                        json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                        json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                        json_insert_pair_into_object(recobj, "message", json_new_string(captured_stderr));
                        json_insert_child(errorDataArr, recobj);
                    }
                }
                else
                {
                    expStatus = ExpToStdoutStatus_Success;
                }

                if (captured_stderr)
                {
                    free(captured_stderr);
                    captured_stderr = NULL;
                }
            }
        }
        else
        {
            expStatus = ExpToStdoutStatus_Success;
            iSeg++;
            continue;
        }

        if (drmsStatus == DRMS_ERROR_INVALIDFILE)
        {
            /* no input segment file, so no error - there is nothing to export because the segment file was never created */
            snprintf(msg, sizeof(msg), "no segment file (segment %s) for this record", segIn->info->name);

            if (!suppress_stderr)
            {
                fprintf(stderr, msg);
                fprintf(stderr, "\n");
            }

            if (makeTar && errorDataArr)
            {
                recobj = json_new_object();
                snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                json_insert_child(errorDataArr, recobj);
            }
        }
        else if (drmsStatus != DRMS_SUCCESS)
        {
            if (drmsStatus == DRMS_ERROR_CANTCOMPRESSFLOAT)
            {
                snprintf(msg, sizeof(msg), "cannot export Rice-compressed floating-point images");
            }
            else
            {
                /* there was an input segment file, but for some reason the export failed */
                snprintf(msg, sizeof(msg), "failure exporting segment %s", segIn->info->name);
            }

            if (!suppress_stderr)
            {
                fprintf(stderr, msg);
                fprintf(stderr, "\n");
            }

            if (makeTar && errorDataArr)
            {
                recobj = json_new_object();
                snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                json_insert_child(errorDataArr, recobj);
            }

            /* stupid FITSIO has no way of dumping its internal buffers without writing data to stdout, but if we encountered
             * an error on export, we do not want to dump buffer contents, whatever they may be, on stdout; so, use a pipe
             * to redirect stdout, then read back from the pipe and drop the data on the floor; there might not actually be
             * any data in the FITSIO internal buffers, so check fitsPtr->Fptr->logfilesize first
             */

            /* closes fitsfile * too (unless there was an IO error) */
            expStatus = DropDataOnFloor(fitsPtr);
            if (expStatus != ExpToStdoutStatus_Success)
            {
                break;
            }
        }
        else
        {
            /* at this point, the entire FITS file is in memory; it does not get flushed to stdout until the
             * FITS file is closed; send message size to caller, then send FITS data
             */
            numBytesFitsFile = fitsPtr->Fptr->logfilesize;
            if (numBytesFitsFile > 0)
            {
                if (numBytesFitsFile + totalBytes > maxTarFileSize)
                {
                    /* tar file is too big */
                    snprintf(msg, sizeof(msg), "the tar file size has exceeded the maximum size of %llu bytes; please consider requesting data for fewer records and Rice-compressing images", maxTarFileSize);

                    if (!suppress_stderr)
                    {
                        fprintf(stderr, msg);
                        fprintf(stderr, "\n");
                    }

                    if (makeTar && errorDataArr)
                    {
                        recobj = json_new_object();
                        snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                        json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                        json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                        json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                        json_insert_child(errorDataArr, recobj);
                    }

                    /* closes fitsfile * too */
                    DropDataOnFloor(fitsPtr);
                    expStatus = ExpToStdoutStatus_TarTooLarge;
                    break;
                }

                if (makeTar)
                {
                    /* dump FITS file to stdout (0-pads header block) */
                    DumpTarFileObjectHeader(stdout, formattedFitsName, numBytesFitsFile);
                }
                else
                {
                    /* dump the name of the file, if it is being requested */
                    if (dumpFileName)
                    {
                        DumpAndPad(stdout, formattedFitsName, strlen(formattedFitsName), FILE_NAME_SIZE, NULL);
                    }
                }

                /* dump FITS-file data */
                fiostat = 0;
                fits_close_file(fitsPtr, &fiostat);
                if (fiostat)
                {
                    snprintf(msg, sizeof(msg), "unable to close and send FITS file");

                    if (!suppress_stderr)
                    {
                        fprintf(stderr, msg);
                        fprintf(stderr, "\n");
                    }

                    if (makeTar && errorDataArr)
                    {
                        recobj = json_new_object();
                        snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                        json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                        json_insert_pair_into_object(recobj, "file", json_new_string(formattedFitsName));
                        json_insert_pair_into_object(recobj, "message", json_new_string(msg));
                        json_insert_child(errorDataArr, recobj);
                    }
                }

                fflush(stdout);

                if (makeTar)
                {
                    /* pad last TAR data block */
                    expStatus = FillBlock(stdout, TAR_BLOCK_SIZE, numBytesFitsFile);
                }

                totalBytes += numBytesFitsFile;
                totalFiles++;

                if (infoDataArr)
                {
                    /* print JSON output for ease of parsing; append to the returned JSON obj's data array:
                     * {
                     *   "status" : 0,
                     *   "msg" : "success",
                     *   "data" : [
                     *              {
                     *                "record": "hmi.Ic_720s[2017.01.09_00:00:00_TAI][3]{continuum}",
                     *                "filename": "/SUM95/D990052480/S00000/continuum.fits"
                     *              },
                     *              {
                     *                ...
                     *              }
                     *            ]
                     * }
                     */
                    recobj = json_new_object();
                    snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                    json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                    json_insert_pair_into_object(recobj, "filename", json_new_string(formattedFitsName));
                    json_insert_child(infoDataArr, recobj);
                }
            }
            else
            {
                if (makeTar && errorDataArr)
                {
                    /* print JSON output for ease of parsing; append to the returned JSON obj's data array:
                     * {
                     *   "data" : [
                     *              {
                     *                "record": "hmi.Ic_720s[2017.01.09_00:00:00_TAI][3]{continuum}",
                     *                "filename": "/SUM95/D990052480/S00000/continuum.fits",
                     *                "message": "no data in segment, so no FITS file was produced"
                     *              },
                     *              {
                     *                ...
                     *              }
                     *            ]
                     * }
                     */
                    recobj = json_new_object();
                    snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, segIn->info->name);
                    json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                    json_insert_pair_into_object(recobj, "filename", json_new_string(formattedFitsName));
                    json_insert_pair_into_object(recobj, "message", json_new_string("no data in segment, so no FITS file was produced"));
                    json_insert_child(errorDataArr, recobj);
                }
            }
        }

        if (!makeTar)
        {
            /* if we are not making a tar file, we are streaming a single FITS file, so we cannot stream more than one segment */
            break;
        }
    } /* seg loop */

    if (last)
    {
        hiter_destroy(&last);
    }

    if (bytesExported)
    {
        *bytesExported = totalBytes;
    }

    if (numFilesExported)
    {
        *numFilesExported = totalFiles;
    }

    /* error only if bad file name template or problems dumping FITSIO buffers - if 0 segments were exported, there is no error */
    return expStatus;
}

/* loop over records */
/* segCompression is an array of FITSIO macros, one for each segment, that specify the type of compression to perform; if NULL, then compress all segments with Rice compression
 */
static ExpToStdoutStatus_t ExportRecordSetToStdout(DRMS_Env_t *env, int makeTar, int dumpFileName, int suppress_stderr, DRMS_RecordSet_t *expRS, const char *ffmt, ExpToStdout_Compression_t *segCompression, int compressAllSegs, const char *classname, const char *mapfile, size_t *bytesExported, size_t maxTarFileSize, size_t *numFilesExported, json_t *infoDataArr, json_t *errorDataArr, char **error_buf)
{
    int drmsStatus = DRMS_SUCCESS;
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;

    int iSet;
    int iRec;
    int nRecs;
    DRMS_Record_t *expRecord = NULL;

    int recsExported = 0;
    int recsAttempted = 0;

    char error_buf_tmp[128];
    size_t sz_error_buf = 256;

    if (error_buf)
    {
        *error_buf = calloc(1, sz_error_buf);
    }

    for (iSet = 0; expStatus == ExpToStdoutStatus_Success && iSet < expRS->ss_n; iSet++)
    {
        nRecs = drms_recordset_getssnrecs(expRS, iSet, &drmsStatus);

        if (drmsStatus != DRMS_SUCCESS)
        {
            if (error_buf && *error_buf)
            {
                snprintf(error_buf_tmp, sizeof(error_buf_tmp), "WARNING: failure calling drms_recordset_getssnrecs(), skipping subset %s\n", expRS->ss_queries[iSet]);
                *error_buf = base_strcatalloc(*error_buf, error_buf_tmp, &sz_error_buf);
            }
        }
        else
        {
            for (iRec = 0; expStatus == ExpToStdoutStatus_Success && iRec < nRecs; iRec++)
            {
                expRecord = drms_recordset_fetchnext(env, expRS, &drmsStatus, NULL, NULL);

                if (!expRecord || drmsStatus != DRMS_SUCCESS)
                {
                    /* exit rec loop - last record was fetched last time */
                    break;
                }

                recsAttempted++;

                /* export each segment file in this record */
                expStatus = ExportRecordToStdout(makeTar, dumpFileName, suppress_stderr, expRecord, ffmt, segCompression, compressAllSegs, classname, mapfile, bytesExported, maxTarFileSize, numFilesExported, infoDataArr, errorDataArr);
                if (expStatus == ExpToStdoutStatus_TarTooLarge)
                {
                    break;
                }
                else if (expStatus == ExpToStdoutStatus_Success)
                {
                    recsExported++;
                }

                /* IF the internal FITSIO buffers have data, there is no way to NOT flush output to stdout;
                 * hopefully this error will not happen often; if the pipe to the parent process breaks,
                 * then we could get into this situation, in which case it does not matter if we spill the
                 * FITSIO buffers onto stdout; if we are here because ExportRecordToStdout() failed for
                 * some other reason, the FITSIO inner buffers are likely empty
                 */


                /* if expStatus != ExpToStdoutStatus_Success, this is not because we could not send the
                 * client a message; it has something to do with the export process itself or the
                 * use of the FITSIO library and it affects this particular DRMS record only; we
                 * already successfully sent the client a status-bad message, so they know to
                 * ignore all data till the next record's data gets returned; in
                 * this case, we want to go on to the next DRMS record, resetting expStatus to
                 * ExpToStdoutStatus_Success */
                 expStatus = ExpToStdoutStatus_Success;
            }
        }
    }

    if (recsAttempted > 0 && recsExported == 0)
    {
        expStatus = ExpToStdoutStatus_AllExportsFailed;
    }

    if (error_buf && *error_buf)
    {
        if (expStatus == ExpToStdoutStatus_Success)
        {
            if (expRS->n > 0 && recsAttempted < expRS->n)
            {
                /* there was some kind of problem with drms_recordset_*() calls so that not all records were processed; but as long as at least 1
                 * attempted export succeeded, then this is not considered a failure */
                snprintf(error_buf_tmp, sizeof(error_buf_tmp), "WARNING: of the %d records to export, attempts to export only %d records were made\n", expRS->n, recsAttempted);
                *error_buf = base_strcatalloc(*error_buf, error_buf_tmp, &sz_error_buf);
            }
        }
        else if (expStatus == ExpToStdoutStatus_TarTooLarge)
        {
            snprintf(error_buf_tmp, sizeof(error_buf_tmp), "ERROR: the tar file size exceeded the limit and has been truncated\n");
            *error_buf = base_strcatalloc(*error_buf, error_buf_tmp, &sz_error_buf);
        }
        else if (expStatus == ExpToStdoutStatus_AllExportsFailed)
        {
            snprintf(error_buf_tmp, sizeof(error_buf_tmp), "ERROR: %d attempts were made to export files, but they all failed\n", recsAttempted);
            *error_buf = base_strcatalloc(*error_buf, error_buf_tmp, &sz_error_buf);
        }
    }

    return expStatus;
}

int DoIt(void)
{
    ExpToStdoutStatus_t expStatus = ExpToStdoutStatus_Success;
    ExpToStdoutStatus_t dump_status = ExpToStdoutStatus_Success;

    int drmsStatus = DRMS_SUCCESS;
    int fiostat = 0;
    fitsfile *fitsPtr = NULL;
    long long tsize = 0; /* total size of export payload in bytes */
    long long tsizeMB = 0; /* total size of export payload in Mbytes */
    void *misspix = NULL;
    const char *rsSpec = NULL;
    const char *fileTemplate = NULL;
    const char *mapClass = NULL;
    const char *mapFile = NULL;
    LinkedList_t *cparmsStrings = NULL;
    const char *ackFile = NULL;
    size_t maxTarFileSize = 0;
    int compressAllSegs = 0;
    int skipTarCreation = 0;
    int dumpFileName = 0;
    int suppress_stderr = 0;
    int makeTar = 1;
    ListNode_t *cparmNode = NULL;
    ExpToStdout_Compression_t *segCompression = NULL;
    int iComp;
    DRMS_RecordSet_t *expRS = NULL;
    char generalErrorBuf[TAR_BLOCK_SIZE]; /* the last file object in the tar file will be a single tar block (makeTar == 1) */
    char *error_buf_tmp = NULL;
    size_t bytesExported = 0;
    size_t numFilesExported = 0;
    json_t *infoRoot = NULL; /* for FILE_LIST_PATH file inside tar file (makeTar == 1) */
    json_t *infoDataArr = NULL;
    json_t *errorRoot = NULL; /* for ERROR_LIST_PATH file inside tar file (makeTar == 1) */
    json_t *errorDataArr = NULL;
    char *infoJson = NULL;
    char *errorJson = NULL;
    char *jsonFileContent = NULL;
    json_t *recobj = NULL;
    char specbuf[1024];
    char numbuf[16];

    /* read and process arguments */
    rsSpec = params_get_str(&cmdparams, ARG_RS_SPEC);
    GetOptionValue(ARG_STRING, ARG_FILE_TEMPLATE, (void *)&fileTemplate);
    GetOptionValue(ARG_STRING, ARG_KEYMAP_CLASS, (void *)&mapClass);
    GetOptionValue(ARG_STRING, ARG_KEYMAP_FILE, (void *)&mapFile);
    GetOptionValue(ARG_STRINGS, ARG_CPARMS_STRING, (void *)&cparmsStrings);
    GetOptionValue(ARG_STRING, ARG_ACK_FILE, (void *)&ackFile);
    GetOptionValue(ARG_INT, ARG_MAX_TAR_FILE_SIZE, (void *)&maxTarFileSize);
    GetOptionValue(ARG_FLAG, ARG_COMPRESS_ALL_SEGS, (void *)&compressAllSegs);
    GetOptionValue(ARG_FLAG, ARG_DO_NOT_CREATE_TAR, (void *)&skipTarCreation);
    GetOptionValue(ARG_FLAG, ARG_DUMP_FILE_NAME, (void *)&dumpFileName);
    GetOptionValue(ARG_FLAG, ARG_SUPPRESS_STDERR, (void *)&suppress_stderr);

    memset(generalErrorBuf, '\0', sizeof(generalErrorBuf));

    makeTar = !skipTarCreation;

    if (makeTar && dumpFileName)
    {
        expStatus = ExpToStdoutStatus_CantDumpFileNameForTarFile;
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        if (makeTar)
        {
            infoRoot = json_new_object();
            infoDataArr = json_new_array();
            json_insert_pair_into_object(infoRoot, "data", infoDataArr);

            errorRoot = json_new_object();
            errorDataArr = json_new_array();
            json_insert_pair_into_object(errorRoot, "data", errorDataArr);
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* map cparms strings to an enum */
        if (cparmsStrings)
        {
            char *cparmStr = NULL;

            segCompression = calloc(1, sizeof(ExpToStdout_Compression_t));

            if (segCompression)
            {
                list_llreset(cparmsStrings);
                iComp = 0;
                while ((cparmNode = list_llnext(cparmsStrings)) != NULL)
                {
                    cparmStr = *(char **)cparmNode;

                    if (strcasecmp(cparmStr, COMPRESSION_NONE) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_NONE;
                    }
                    else if (strcasecmp(cparmStr, COMPRESSION_RICE) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_RICE;
                    }
                    else if (strcasecmp(cparmStr, COMPRESSION_GZIP1) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_GZIP1;
                    }
    #if CFITSIO_MAJOR >= 4 || (CFITSIO_MAJOR == 3 && CFITSIO_MINOR >= 27)
                    else if (strcasecmp(cparmStr, COMPRESSION_GZIP2) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_GZIP2;
                    }
    #endif
                    else if (strcasecmp(cparmStr, COMPRESSION_PLIO) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_PLIO;
                    }
                    else if (strcasecmp(cparmStr, COMPRESSION_HCOMP) == 0)
                    {
                        segCompression[iComp] = ExpToStdout_Compression_HCOMP;
                    }
                    else
                    {
                        if (sizeof(generalErrorBuf) - strlen(generalErrorBuf) > 0)
                        {
                            snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "invalid compression-string argument element %s\n", cparmStr);
                        }
                        expStatus = ExpToStdoutStatus_InvalidArgs;
                        break;
                    }

                    iComp++;
                }

                if (expStatus == ExpToStdoutStatus_Success && iComp != 1 && compressAllSegs)
                {
                    if (sizeof(generalErrorBuf) - strlen(generalErrorBuf) > 0)
                    {
                        snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "invalid combination of %s and %s arguments\n", ARG_CPARMS_STRING, ARG_COMPRESS_ALL_SEGS);
                    }
                    expStatus = ExpToStdoutStatus_InvalidArgs;
                }
            }
            else
            {
                expStatus = ExpToStdoutStatus_OutOfMemory;
            }
        }
        else
        {
            /* default is all rice all the time */
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        expRS = drms_open_records(drms_env, rsSpec, &drmsStatus);
        if (!expRS || drmsStatus != DRMS_SUCCESS)
        {
            if (sizeof(generalErrorBuf) - strlen(generalErrorBuf) > 0)
            {
                snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "unable to open records for specification %s\n", rsSpec);
            }
            expStatus = ExpToStdoutStatus_DRMS;
        }
        else
        {
            if (skipTarCreation && expRS->n > 1)
            {
                expStatus = ExpToStdoutStatus_MoreThanOneFileToExport;
            }
            else
            {
            }
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        if (makeTar && maxTarFileSize > MAX_MAX_TAR_FILE_SIZE)
        {
            if (sizeof(generalErrorBuf) - strlen(generalErrorBuf) > 0)
            {
                snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "maximum tar file size argument, %llu, exceeds limit of %llu bytes\n", maxTarFileSize, MAX_MAX_TAR_FILE_SIZE);
            }
            expStatus = ExpToStdoutStatus_InvalidArgs;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* stage records to reduce number of calls to SUMS */
        if (drms_stage_records(expRS, 1, 0) != DRMS_SUCCESS)
        {
            if (sizeof(generalErrorBuf) - strlen(generalErrorBuf) > 0)
            {
                snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "unable to stage records for specification %s\n", rsSpec);
            }
            expStatus = ExpToStdoutStatus_DRMS;
        }
    }

    if (expStatus == ExpToStdoutStatus_Success)
    {
        /* at this point, there has been no error; it may turn out that the tar file dumped is bad, but we cannot tell
         * the caller that because the failure could happen anywhere during the dump process; the caller will detect
         * the problem only after there is an attempt to use the tar file
         */

        /* create a TAR file object header block plus data blocks for each FITS file that is being exported */

        /* since the following call dives into lib DRMS, it could print error and warnings messages to stderr; capture those if we are
         * suppressing writing to stderr */
        expStatus = ExportRecordSetToStdout(drms_env, makeTar, dumpFileName, suppress_stderr, expRS, fileTemplate, segCompression, compressAllSegs, mapClass, mapFile, &bytesExported, maxTarFileSize, &numFilesExported, infoDataArr, errorDataArr, &error_buf_tmp);

        if (error_buf_tmp)
        {
            if (*error_buf_tmp != '\0')
            {
                snprintf(generalErrorBuf + strlen(generalErrorBuf), sizeof(generalErrorBuf) - strlen(generalErrorBuf), "%s", error_buf_tmp);
            }

            free(error_buf_tmp);
            error_buf_tmp = NULL;
        }
    }
    else if (errorRoot)
    {
        char error_buf_msg[512];

        /* we did not call ExportRecordSetToStdout() - an error occurred before any FITS file was dumped;
         * loop through all records and print the same error message for each */
        snprintf(error_buf_msg, sizeof(error_buf_msg), "failure occurred before first record was processed; see %s for general information\n", ERROR_PATH);

        /* write the same message for every segment */
        if (expRS)
        {
            DRMS_Record_t *expRecord = NULL;
            char recordSpec[DRMS_MAXQUERYLEN];
            HIterator_t *last = NULL;
            DRMS_Segment_t *seg = NULL;

            drms_recordset_fetchnext_setcurrent(expRS, -1);

            while ((expRecord = drms_recordset_fetchnext(drms_env, expRS, &drmsStatus, NULL, NULL)) != NULL)
            {
                drms_sprint_rec_query(recordSpec, expRecord);

                while ((seg = drms_record_nextseg(expRecord, &last, 0)) != NULL)
                {
                    recobj = json_new_object();
                    snprintf(specbuf, sizeof(specbuf), "%s{%s}", recordSpec, seg->info->name);
                    json_insert_pair_into_object(recobj, "record", json_new_string(specbuf));
                    json_insert_pair_into_object(recobj, "segment", json_new_string(seg->info->name));
                    json_insert_pair_into_object(recobj, "message", json_new_string(error_buf_msg));
                    json_insert_child(errorDataArr, recobj);
                }
            }

            if (last)
            {
                hiter_destroy(&last);
            }

            json_tree_to_string(errorRoot, &errorJson);
        }
    }

    if (infoRoot)
    {
        /* makeTar == 1 */

        /* must print out infoRoot before errorRoot */

        /* if we never got to the point of dumping the tar file, then there is no info to provide the caller;
         * the info buffer will have content only if at least one FITS file was dumped
         */

        /* because some code that uses this program expects the properties of a jsoc_fetch response, let's add
         * them now
         */
        snprintf(numbuf, sizeof(numbuf), "0");

        json_insert_pair_into_object(infoRoot, "status", json_new_number(numbuf));
        json_insert_pair_into_object(infoRoot, "requestid", json_new_null());
        json_insert_pair_into_object(infoRoot, "method", json_new_string("url_direct"));
        json_insert_pair_into_object(infoRoot, "protocol", json_new_string("FITS"));
        json_insert_pair_into_object(infoRoot, "dir", json_new_null());
        json_insert_pair_into_object(infoRoot, "wait", json_new_number(numbuf));

        json_tree_to_string(infoRoot, &infoJson);
        jsonFileContent = calloc(1, strlen(infoJson) + 2);
        strcat(jsonFileContent, infoJson);
        jsonFileContent[strlen(jsonFileContent)] = '\n';

        /* 0-pads to TAR block size */
        dump_status = WriteFileBuffer(stdout, FILE_LIST_PATH, jsonFileContent, strlen(jsonFileContent));

        free(jsonFileContent);
        jsonFileContent = NULL;
        free(infoJson);
        infoJson = NULL;
        json_free_value(&infoRoot);
    }

    if (errorRoot && !errorJson)
    {
        /* makeTar == 1 */

        /* ran ExportRecordSetToStdout(), there may or may not have been a failure */
        json_tree_to_string(errorRoot, &errorJson);
    }

    if (errorJson)
    {
        jsonFileContent = calloc(1, strlen(errorJson) + 2);
        strcat(jsonFileContent, errorJson);
        jsonFileContent[strlen(jsonFileContent)] = '\n';

        /* 0-pads to TAR block size */
        dump_status = WriteFileBuffer(stdout, ERROR_LIST_PATH, jsonFileContent, strlen(jsonFileContent));

        free(jsonFileContent);
        jsonFileContent = NULL;
        free(errorJson);
        errorJson = NULL;
    }

    /* regardless of error, we dump all error (ASCII) messages into the TAR file */
    if (errorRoot)
    {
        /* makeTar == 1 */
        json_free_value(&errorRoot);
    }

    if (makeTar && ackFile && *ackFile)
    {
        /* the VSO workflow expects the ack file to exist, regardless of the existence of catastrophic errors */
        dump_status = WriteAckFile(stdout, ackFile);
    }

    /* dump a general error message if one exists */
    if (*generalErrorBuf)
    {
        if (makeTar)
        {
            dump_status = WriteFileBuffer(stdout, ERROR_PATH, generalErrorBuf, strlen(generalErrorBuf));

            *generalErrorBuf = '\0';
        }
        else if (!suppress_stderr)
        {
            fprintf(stderr, generalErrorBuf);
        }
    }

    if (makeTar)
    {
        /* write the end-of-archive marker (1024 zero bytes) */
        /* pad - fill up last 512 block with zeroes */
        dump_status = DumpPadding(stdout, 0, TAR_BLOCK_SIZE * 2, NULL);
    }

    /* if expStatus != ExpToStdoutStatus_Success, there was some error before dumping the tar file content; if not,
     * then dump_status implies an error dumping to the tar file
     */
    expStatus = ((expStatus != ExpToStdoutStatus_Success) ? expStatus : dump_status);

    if (expRS)
    {
        drms_close_records(expRS, DRMS_FREE_RECORD);
    }

    if (cparmsStrings)
    {
        list_llfree(&cparmsStrings);
        cparmsStrings = NULL;
    }

    return expStatus;
}
