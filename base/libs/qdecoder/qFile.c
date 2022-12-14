/*
 * Copyright 2008 The qDecoder Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE QDECODER PROJECT ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE QDECODER PROJECT BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file qFile.c File Handling API
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "qDecoder.h"
#include "qInternal.h"

/**
 * Lock file
 *
 * @param fd		file descriptor
 *
 * @return		true if successful, otherwise returns false.
 *
 * @code
 *   // for file descriptor
 *   int fd = open(...);
 *   if(qFileLock(fd) == true) {
 *     (...atomic file access...)
 *     qFileUnlock(fd);
 *   }
 *
 *   // for FILE stream object
 *   FILE *fp = fopen(...);
 *   int fd = fileno(fp);
 *   if(qFileLock(fd) == true) {
 *     (...atomic file access...)
 *     qFileUnlock(fd);
 *   }
 * @endcode
 */
bool qFileLock(int fd) {
#ifdef _WIN32
	return false;
#else
	int ret = flock(fd, LOCK_EX);
	if(ret == 0) return true;
	return false;
#endif
}

/**
 * Unlock file which is locked by qFileLock()
 *
 * @param fd		file descriptor
 *
 * @return		true if successful, otherwise returns false.
 */
bool qFileUnlock(int fd) {
#ifdef _WIN32
	return false;
#else
	int ret = flock(fd, LOCK_EX);
	if(ret == 0) return true;
	return false;
#endif
}

/**
 * Check file existence.
 *
 * @param filepath	file or directory path
 *
 * @return		true if exists, otherwise returns false;
 */
bool qFileExist(const char *filepath) {
	struct stat finfo;
	if (stat(filepath, &finfo) < 0) return false;
	return true;
}

/**
 * Get filename from filepath
 *
 * @param filepath	file or directory path
 *
 * @return		malloced filename string
 */
char *qFileGetName(const char *filepath) {
	char *path = strdup(filepath);
	char *bname = basename(path);
	char *filename = strdup(bname);
	free(path);
	return filename;
}

/**
 * Get directory suffix from filepath
 *
 * @param filepath	file or directory path
 *
 * @return		malloced filepath string
 */
char *qFileGetDir(const char *filepath) {
	char *path = strdup(filepath);
	char *dname = dirname(path);
	char *dir = strdup(dname);
	free(path);
	return dir;
}

/**
 * Get extension from filepath.
 *
 * @param filepath	file or directory path
 *
 * @return		malloced extension string which is converted to lower case.
 */
char *qFileGetExt(const char *filepath) {
#define MAX_EXTENSION_LENGTH		(5)
	char *filename = qFileGetName(filepath);
	char *p = strrchr(filename, '.');
	char *ext = NULL;
	if(p != NULL && strlen(p+1) <= MAX_EXTENSION_LENGTH && qStrIsAlnum(p+1) == true) {
		ext = strdup(p+1);
		qStrLower(ext);
	} else {
		ext = strdup("");
	}

	free(filename);
	return ext;
}

/**
 * Get file size.
 *
 * @param filepath	file or directory path
 *
 * @return		the file size if exists, otherwise returns -1.
 */
off_t qFileGetSize(const char *filepath) {
	struct stat finfo;
	if (stat(filepath, &finfo) < 0) return -1;
	return finfo.st_size;
}

/**
 * Transfer data between file descriptors
 *
 * @param outfd		output file descriptor
 * @param infd		input file descriptor
 * @param nbytes	the number of bytes to copy between file descriptors. 0 means transfer until end of infd.
 *
 * @return		the number of bytes written to outfd.
 */
off_t qFileSend(int outfd, int infd, off_t nbytes) {
#define MAX_FILESEND_CHUNK_SIZE		(32 * 1024)
	if(nbytes == 0) return 0;

	char buf[MAX_FILESEND_CHUNK_SIZE];

	off_t sent = 0; // total size sent
	while(sent < nbytes) {
		size_t sendsize;	// this time sending size
		if(nbytes - sent <= sizeof(buf)) sendsize = nbytes - sent;
		else sendsize = sizeof(buf);

		// read
		ssize_t retr = read(infd, buf, sendsize);
		DEBUG("read %zd", retr);
		if (retr <= 0) {
			if(sent == 0) return -1;
			break;
		}

		// write
		ssize_t retw = _q_write(outfd, buf, retr);
		DEBUG("write %zd", retw);
		if(retw <= 0) {
			if(sent == 0) return -1;
			break;
		}

		sent += retw;
		if(retr != retw) {
			DEBUG("size mismatch %zd, %zd", retr, retw);
			break;
		}
	}

	return sent;
}

/**
 * Load file into memory.
 *
 * @param filepath	file path
 * @param nbytes	has two purpost, one is to set how many bytes are readed. the other is actual the number loaded bytes will be stored. nbytes must be point 0 or NULL to read entire file.
 *
 *
 * @return		allocated memory pointer if successful, otherwise returns NULL.
 *
 * @code
 *   // loading text file
 *   char *text = (char *)qFileLoad("/tmp/text.txt", NULL);
 *
 *   // loading binary file
 *   int binlen = 0;
 *   char *bin = (char *)qFileLoad("/tmp/binary.bin", &binlen);
 *
 *   // loading partial
 *   int binlen = 10;
 *   char *bin = (char *)qFileLoad("/tmp/binary.bin", &binlen);
 * @endcode
 *
 * @note
 * This method actually allocates memory more than 1 bytes than filesize then append
 * NULL character at the end. For example, when the file size is 10 bytes long, 10+1
 * bytes will allocated and the last byte is always NULL character. So you can load
 * text file and use without appending NULL character. By the way, *size still will
 * be returned the actual file size of 10.
 */
void *qFileLoad(const char *filepath, size_t *nbytes) {
	int fd;
	if((fd = open(filepath, O_RDONLY, 0)) < 0) return NULL;

	struct stat fs;
	if (fstat(fd, &fs) < 0) {
		close(fd);
		return NULL;
	}

	size_t size = fs.st_size;
	if(nbytes != NULL && *nbytes > 0 && *nbytes < fs.st_size) size = *nbytes;

	void *buf = malloc(size + 1);
	if(buf == NULL) {
		close(fd);
		return NULL;
	}

	ssize_t count = read(fd, buf, size);
	close(fd);

	if (count != size) {
		free(buf);
		return NULL;
	}

	((char*)buf)[count] = '\0';

	if(nbytes != NULL) *nbytes = count;
	return buf;
}

/**
 * Load file stream which has unknown size into memory.
 *
 * @param fp		FILE pointer
 * @param nbytes	has two purpost, one is to set how many bytes are readed. the other is actual the number loaded bytes will be stored. nbytes must be point 0 or NULL to read end of stream.
 *
 * @return		allocated memory pointer if successful, otherwise returns NULL.
 *
 * @note
 * This method append NULL character at the end of stream. but nbytes only counts
 * actual readed bytes.
 */
void *qFileRead(FILE *fp, size_t *nbytes) {
	size_t memsize;
	size_t c_count;
	size_t size = 0;
	char *data = NULL;

	if(nbytes != NULL && *nbytes > 0) size = *nbytes;

	int c;
	for (memsize = 1024, c_count = 0; (c = fgetc(fp)) != EOF;) {
		if(size > 0 && c_count == size) break;

		if (c_count == 0) {
			data = (char*)malloc(sizeof(char) * memsize);
			if (data == NULL) {
				DEBUG("Memory allocation failed.");
				return NULL;
			}
		} else if (c_count == memsize - 1) {
			memsize *= 2;

			/* Here, we do not use realloc(). Because sometimes it is unstable. */
			char *datatmp = (char*)malloc(sizeof(char) * (memsize + 1));
			if (datatmp == NULL) {
				DEBUG("Memory allocation failed.");
				free(data);
				return NULL;
			}
			memcpy(datatmp, data, c_count);
			free(data);
			data = datatmp;
		}
		data[c_count++] = (char)c;
	}

	if (c_count == 0 && c == EOF) return NULL;
	data[c_count] = '\0';

	if(nbytes != NULL) *nbytes = c_count;

	return (void*)data;
}

/**
 * Read string. Same as fgets but can be used for unlimited string line.
 *
 * @param fp		FILE pointer
 *
 * @return		allocated memory pointer if successful, otherwise returns NULL.
 */
char *qFileReadLine(FILE *fp) {
	int memsize;
	int c, c_count;
	char *string = NULL;

	for (memsize = 1024, c_count = 0; (c = fgetc(fp)) != EOF;) {
		if (c_count == 0) {
			string = (char *)malloc(sizeof(char) * memsize);
			if (string == NULL) {
				DEBUG("Memory allocation failed.");
				return NULL;
			}
		} else if (c_count == memsize - 1) {
			char *stringtmp;

			memsize *= 2;

			/* Here, we do not use realloc(). Because sometimes it is unstable. */
			stringtmp = (char *)malloc(sizeof(char) * (memsize + 1));
			if (stringtmp == NULL) {
				DEBUG("Memory allocation failed.");
				free(string);
				return NULL;
			}
			memcpy(stringtmp, string, c_count);
			free(string);
			string = stringtmp;
		}
		string[c_count++] = (char)c;
		if ((char)c == '\n') break;
	}

	if (c_count == 0 && c == EOF) return NULL;
	string[c_count] = '\0';

	return string;
}

/**
 * Save to file.
 *
 * @param filepath	file path
 * @param buf		data
 * @param size		the number of bytes to save
 * @param append	false for new(if exists truncate), true for appending
 *
 * @return		the number of bytes written if successful, otherwise returns -1.
 *
 * @code
 *   // save text
 *   char *text = "hello";
 *   qFileSave("/tmp/text.txt", (void*)text, strlen(text), false);
 *
 *   // save binary
 *   int integer1 = 75;
 *   qFileSave("/tmp/integer.bin, (void*)&integer, sizeof(int));
 * @endcode
 */
ssize_t qFileSave(const char *filepath, const void *buf, size_t size, bool append) {
	int fd;

	if(append == false) fd = open(filepath, O_CREAT|O_WRONLY|O_TRUNC, DEF_FILE_MODE);
	else fd = open(filepath, O_CREAT|O_WRONLY|O_APPEND, DEF_FILE_MODE);
	if(fd < 0) return -1;

	ssize_t count = write(fd, buf, size);
	close(fd);

	return count;
}
