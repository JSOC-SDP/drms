//#define DEBUG_MEM
//#define DEBUG

#define DRMS_CLIENT

#include "jsoc.h"
#include "drms.h"
#ifdef DEBUG_MEM
#include "xmem.h"
#endif
#include "tee.h"
#include <signal.h>
						    /* for drms_start_server */
#include "serverdefs.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include "cfortran.h"
#include "jsoc_main.h"
#include "drms_env.h"
#include "cmdparams_priv.h"

CmdParams_t cmdparams;
/* Global DRMS Environment handle. */
DRMS_Env_t *drms_env;

#ifndef FLIB
/* For FORTRAN modules, gModArgs is defined in jsoc_main_sock_f.c from a common block
 * containing the arguments.  jsoc_main_sock_f.c allocates memory for gModArgs, and
 * then deallocates the memory just before termination.
 */
ModuleArgs_t *gModArgs = module_args;
#endif

CmdParams_t *GetGlobalCmdParams()
{
  return &cmdparams;
}

/* The atexit function can't take arguments...so make a global. */
const char *mn = NULL;

static pid_t drms_start_server (int verbose, int dolog);

   /* Remind the user that the DRMS session is rolled back if exit is called */
static void atexit_action (void) {
  fprintf (stderr, "WARNING: DRMS module %s called exit.\nThe DRMS session"
      " will be aborted and the database rolled back.\n", mn);
}

static int FreeCmdparams(void *data)
{
   cmdparams_freeall(&cmdparams);
   memset(&cmdparams, 0, sizeof(CmdParams_t));
   return 0;
}

int JSOCMAIN_Init(int argc,
		  char **argv,
		  const char *module_name,
		  int *dolog,
		  int *verbose,
		  pid_t *drms_server_pid,
		  pid_t *tee_pid,
		  int *cont)
{
   int status;
   int quiet;
   int printrel = 0;
   char reservebuf[128];
   int selfstart = 0;

   if (cont)
   {
      *cont = 0;
   }

   mn = module_name;

#ifdef DEBUG_MEM
   xmem_config (1, 1, 1, 1, 1000000, 1,0, 0);
#endif
   /* Parse command line parameters */
   snprintf(reservebuf, sizeof(reservebuf), "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", "L,Q,V,jsocmodver", kARCHIVEARG, kRETENTIONARG, kNewSuRetention, kQUERYMEMARG, kLoopConn, kDBTimeOut, kCreateShadows, kDBUtf8ClientEncoding, DRMS_ARG_PRINT_SQL);
   cmdparams_reserve(&cmdparams, reservebuf, "jsocmain");

   status = cmdparams_parse (&cmdparams, argc, argv);
   if (status == CMDPARAMS_QUERYMODE) {
      cmdparams_usage (argv[0]);
      return 0;
   } else if (status == CMDPARAMS_NODEFAULT) {
      fprintf (stderr, "For usage, type %s [-H|--help]\n", argv[0]);
      return 0;
   } else if (status < 0) {
      fprintf (stderr, "Error: Command line parsing failed. Aborting.\n");
      fprintf (stderr, "For usage, type %s [-H|--help]\n", argv[0]);
      return 1;
   }

   printrel = cmdparams_isflagset(&cmdparams, "jsocmodver");

   if (printrel)
   {
      char verstr[32];
      int isdev = 0;

      jsoc_getversion(verstr, sizeof(verstr), &isdev);
      fprintf(stdout,
              "Module '%s' JSOC version is '%s' (%s)\n",
              module_name,
              verstr,
              isdev ? "development" : "release");
      return 0;
   }

   *verbose = (cmdparams_exists (&cmdparams, "V") &&
	      cmdparams_get_int (&cmdparams, "V", NULL) != 0);
   if (*verbose) cmdparams_printall (&cmdparams);
   quiet = (cmdparams_exists (&cmdparams, "Q") &&
	    cmdparams_get_int (&cmdparams, "Q", NULL) != 0);
   *dolog = (cmdparams_exists (&cmdparams, "L") &&
	    cmdparams_get_int (&cmdparams, "L", NULL) != 0);
   if (!cmdparams_exists (&cmdparams, kQUERYMEMARG))
     cmdparams_set (&cmdparams, kQUERYMEMARG, "512");
   /* if not already in a DRMS session make one */
   if (!cmdparams_exists (&cmdparams, "DRMSSESSION")) {
      if ((*drms_server_pid = drms_start_server (*verbose, *dolog)) < 0) {
	 fprintf (stderr,
		  "Couldn't connect to a DRMS server via drms_start_server.\n");
	 return 1;
      }

      /* set self-start flag so we know that this module isn't sharing drms_server with others */
      selfstart = 1;
   }
   /* DRMS Prolog */
   if (cmdparams_exists (&cmdparams, "DRMSSESSION")) {
      char filename_e[1024], filename_o[1024];
      const char *drmssession = cmdparams_get_str (&cmdparams, "DRMSSESSION", NULL);
      const char *jsoc_dbuser = cmdparams_get_str (&cmdparams, "JSOC_DBUSER", NULL);
      const char *jsoc_dbpasswd = cmdparams_get_str (&cmdparams, "JSOC_DBPASSWD", NULL);
      const char *jsoc_dbname = cmdparams_get_str (&cmdparams, "JSOC_DBNAME", NULL);
      drms_env = drms_open (drmssession, jsoc_dbuser, jsoc_dbpasswd, jsoc_dbname, NULL);
      if (drms_env == NULL) {
	 fprintf (stderr, "Couldn't connect to DRMS.\n");
	 return 1;
      }

      drms_env->selfstart = selfstart;
      drms_env->query_mem = cmdparams_get_int (&cmdparams, kQUERYMEMARG, NULL);

      if (*dolog) {
	 if (save_stdeo()) {
	    printf ("Can't save stdout and stderr\n");
	    return 1;
	 }
	 /* This program is now running in a DRMS session.
	    Redirect or tee stdout and stderr to the session log directory. */
	 CHECKSNPRINTF(snprintf (filename_o, 1023, "%s/%s.%04d.stdout.gz",
				 drms_env->session->sudir, module_name, drms_env->session->clientid), 1023);
	 CHECKSNPRINTF(snprintf (filename_e, 1023, "%s/%s.%04d.stderr.gz",
				 drms_env->session->sudir, module_name, drms_env->session->clientid), 1023);

	 if (!quiet) {
	    if ((*tee_pid = tee_stdio (filename_o, 0644, filename_e, 0644)) < 0)
	      return -1;
	 } else if (redirect_stdio (filename_o, 0644, filename_e, 0644))
	   return -1;
      }
#ifndef IDLLIB
      /* Don't register an atexit function because this code is running inside
       * the IDL process.  When IDL exits, it always either returns from its own
       * main(), or it calls exit().  Therefore, atexit_action() is always called
       * from an IDL session.  Modules, on the other hand, exit by calling _exit()
       * when no errors have occurred.  atexit() should only be used from DRMS modules
       * where exit by anything other than _exit() denotes an error, and _exit()
       * denotes success.
       */
      atexit (atexit_action);
#endif
   }

   /* Initialize global things. */

   /* Block signals INT, QUIT, TERM, and USR1. They will explicitly
      handled by the signal thread created below. */
#ifndef DEBUG
   sigemptyset(&drms_env->signal_mask);
   sigaddset(&drms_env->signal_mask, SIGINT);
   sigaddset(&drms_env->signal_mask, SIGQUIT);
   sigaddset(&drms_env->signal_mask, SIGTERM);
   sigaddset(&drms_env->signal_mask, SIGUSR1);
   sigaddset(&drms_env->signal_mask, SIGUSR2);

   if( (status = pthread_sigmask(SIG_BLOCK, &drms_env->signal_mask, &drms_env->old_signal_mask)))
   {
      fprintf(stderr,"pthread_sigmask call failed with status = %d\n", status);
      exit(1);
   }

   drms_env->main_thread = pthread_self();

   /* Free cmd-params (valgrind reports this - let's just clean up so it doesn't show up on
    * valgrind's radar). */
   CleanerData_t cleaner = {(pFn_Cleaner_t)FreeCmdparams, (void *)NULL};

   drms_client_registercleaner(drms_env, &cleaner);

   /* Spawn a thread that handles signals and controls server
      abort or shutdown. */
   if( (status = pthread_create(&drms_env->signal_thread, NULL, &drms_signal_thread,
                                (void *) drms_env)) )
   {
      fprintf(stderr,"Thread creation failed: %d\n", status);
      exit(1);
   }

#endif

   /* continue with calling module or otherwise interacting with DRMS. */
   if (cont)
   {
      *cont = 1;
   }

   return 0;
}

int JSOCMAIN_Term(int dolog, int verbose, pid_t drms_server_pid, pid_t tee_pid, int abort_flag)
{
   int status;

#ifdef DEBUG
   printf ("Module %s returned with status = %d\n", mn, abort_flag);
#endif

   /* This will close all fitsfile pointers, saving changes to the underlying fits files.
    * This must be done in the module process as that is the process that maintains the
    * list of open fitsfiles (see drms_server_commit() for more information). */
   if (!abort_flag)
   {
      drms_fitsrw_term(drms_env->verbose);
   }

   /* DRMS Epilog:
      If abort_flag=0 all data records created by this module are inserted
      into the database and will become permanent at the next session commit.
      If abort_flag=1 all data inserted into the database since the last
      session commit are rolled back and the DRMS session is aborted.
   */
   if (cmdparams_exists (&cmdparams, "DRMSSESSION")) {
      /* NOTICE: Some errors on the server side (e.g. failure to
	 communicate with SUMS) will make drms_abort or drms_close fail with
	 error message "readn error: Connection reset by peer" because the
	 server is already stopped and has closed the socket connection.
	 This is not a problem since the server will already have shut itself
	 down cleanly.
      */

      /* This will also cause global DRMS memory to be freed (like base_cleanup stuff) -
       * okay to do this since drms_free_env() knows what to do in a client environment.
       */
      if (abort_flag) drms_abort (drms_env);
      else drms_close (drms_env, DRMS_INSERT_RECORD);
   }

   if (dolog) {
      fclose (stdout);
      fclose (stderr);
      if (tee_pid) {
	 waitpid (tee_pid, &status, 0);
	 if (status) printf ("Problem returning from tee\n");
      }
      if (restore_stdeo ()) printf ("Can't restore stderr and stdout\n");
   }

   if (drms_server_pid) {	   /* mimic drms_run after command execution */
      /* Stop the DRMS server */
      if (abort_flag) {
	 if (verbose)
	   printf ("Command returned an error code. Rolling back database.\n");
	 kill (drms_server_pid, SIGTERM);
      }
      else {
	 if (verbose)
	   printf ("Command finished successfully. Commiting data to database.\n");
	 if (kill (drms_server_pid, SIGUSR1)) {
	    perror ("SIGUSR1 attempt failed to stop server jsoc_main");
	    printf ("drms_pid = %d\n", drms_server_pid);
	 }
      }
      if (waitpid (drms_server_pid, &status, 0) < 0) perror ("waitpid error");
      if (verbose) printf ("drms_server returned with status = %d\n", status);
   }

   cmdparams_freeall (&cmdparams);

#ifdef DEBUG_MEM
   xmem_leakreport ();
#endif
   fflush (stdout);
   fflush (stderr);

   return status;
}

int JSOCMAIN_Main(int argc, char **argv, const char *module_name, int (*CallDoIt)(void))
{
   int abort_flag = 0;
   int cont;
   int ret;

   /* Passed between Init and Term. */
   int dolog;
   int verbose;
   pid_t drms_server_pid = 0;
   pid_t tee_pid = 0;


   ret = JSOCMAIN_Init(argc,
		       argv,
		       module_name,
		       &dolog,
		       &verbose,
		       &drms_server_pid,
		       &tee_pid,
		       &cont);

   if (!cont)
   {
      return ret;
   }

   /* Call main module function */
   if (CallDoIt)
   {
      abort_flag = (*CallDoIt)();
   }

   sem_t *sdsem = drms_client_getsdsem();

   if (sdsem)
   {
      sem_wait(sdsem);
   }

   if (drms_client_getsd() != kSHUTDOWN_UNINITIATED)
   {
      /* signal thread is already shutting down, just wait for signal thread to finish
       * (which it won't do, because it is going to call exit, so this is an indefinite sleep). */
      if (sdsem)
      {
         sem_post(sdsem);
      }

      pthread_join(drms_env->signal_thread, NULL);
   }
   else
   {
      /* Tell signal thread not to accept shutdown requests, because main is shutting down. */
      drms_client_setsd(kSHUTDOWN_BYMAIN);

      if (sdsem)
      {
         sem_post(sdsem);
      }

      JSOCMAIN_Term(dolog, verbose, drms_server_pid, tee_pid, abort_flag);
   }

   return(abort_flag);
}

	     /*  drms_start_server - mimics initial code in drms_run script  */

pid_t drms_start_server (int verbose, int dolog)  {
    const char *dbhost;
    char *dbuser, *dbpasswd, *dbname, *sessionns;
    char *dbport = NULL;
    char dbHostAndPort[64];
  int query_mem, server_wait;
  int16_t retention;
  int16_t newsuretention;
  int archive;
    int dbtimeout;
  int loopconn;
    int createshadows = 0;
    int dbutf8clientencoding = 0;
    int print_sql_only = 0;
  char drms_session[DRMS_MAXPATHLEN];
  char drms_host[DRMS_MAXPATHLEN];
  char drms_port[DRMS_MAXPATHLEN];
  int status = 0;


	/* Get hostname, user, passwd and database name for establishing
				    a connection to the DRMS database server */

    /* SERVER does not contain port information. Yet when dbhost is used in db_connect(), that function
     * parses the value looking for an optional port number. So if you didn't provide the JSOC_DBHOST
     * then there was no way to connect to the db with a port other than the default port that the
     * db listens on for incoming connections (which is usually 5432).
     *
     * I changed this so that masterlists uses the DRMSPGPORT macro to define the port to connect to.
     * If by chance somebody has appeneded the port number to the server name in SERVER, and that
     * conflicts with the value in DRMSPGPORT, then DRMSPGPORT wins, and a warning message is printed.
     *
     * --ART (2014.08.20)
     */

  if ((dbhost = cmdparams_get_str (&cmdparams, "JSOC_DBHOST", NULL)) == NULL)
    {
        const char *sep = NULL;

        dbhost =  SERVER;
        dbport = DRMSPGPORT;

        /* Check for conflicting port numbers. */
        if ((sep = strchr(dbhost, ':')) != NULL)
        {
            if (strcmp(sep + 1, dbport) != 0)
            {
                char *tmpBuf = strdup(dbhost);

                if (tmpBuf)
                {
                    tmpBuf[sep - dbhost] = '\0';
                    fprintf(stderr, "WARNING: the port number in the SERVER localization parameter (%s) and in DRMSPGPORT (%s) conflict.\nThe DRMSPGPORT value will be used.\n", sep + 1, DRMSPGPORT);

                    snprintf(dbHostAndPort, sizeof(dbHostAndPort), "%s:%s", tmpBuf, dbport);
                    free(tmpBuf);
                    tmpBuf = NULL;
                }
                else
                {
                    fprintf(stderr, "Out of memory.\n");
                    return 1;
                }
            }
            else
            {
                snprintf(dbHostAndPort, sizeof(dbHostAndPort), "%s", dbhost);
            }
        }
        else
        {
            snprintf(dbHostAndPort, sizeof(dbHostAndPort), "%s:%s", dbhost, dbport);
        }
    }
    else
    {
        snprintf(dbHostAndPort, sizeof(dbHostAndPort), "%s", dbhost);
    }

  if ((dbname = cmdparams_get_str (&cmdparams, "JSOC_DBNAME", NULL)) == NULL)
    dbname = DBNAME;
  if ((dbuser = cmdparams_get_str (&cmdparams, "JSOC_DBUSER", NULL)) == NULL)
    dbuser = USER;
  if ((dbpasswd = cmdparams_get_str (&cmdparams, "JSOC_DBPASSWD", NULL)) == NULL)
    dbpasswd = PASSWD;
  sessionns = cmdparams_get_str (&cmdparams, "JSOC_SESSIONNS", NULL);

  archive = INT_MIN;
  if (drms_cmdparams_exists(&cmdparams, kARCHIVEARG)) {
     archive = drms_cmdparams_get_int(&cmdparams, kARCHIVEARG, NULL);
  }

    char errbuf[128];

    retention = INT16_MIN;
    if (drms_cmdparams_exists(&cmdparams, kRETENTIONARG))
    {
        retention = drms_cmdparams_get_int16(&cmdparams, kRETENTIONARG, &status);
        if (status != DRMS_SUCCESS)
        {
            if (status == DRMS_ERROR_INVALIDCMDARGCONV)
            {
                snprintf(errbuf, sizeof(errbuf), "The value for %s must be a 15-bit positive integer.", kRETENTIONARG);
                fprintf(stderr, errbuf);
            }

            snprintf(errbuf, sizeof(errbuf), "Invalid value for %s.", kRETENTIONARG);
            fprintf(stderr, errbuf);
            return 1;
        }
        else if (retention < 0)
        {
            snprintf(errbuf, sizeof(errbuf), "The value for %s must be a 15-bit positive integer.", kRETENTIONARG);
            fprintf(stderr, errbuf);
            return 1;
        }
        else
        {
            retention = (int16_t)(retention & 0x7FFF);
        }
    }

    newsuretention = INT16_MIN;
    if (drms_cmdparams_exists(&cmdparams, kNewSuRetention))
    {
        newsuretention = drms_cmdparams_get_int16(&cmdparams, kNewSuRetention, &status);
        if (status != DRMS_SUCCESS)
        {
            if (status == DRMS_ERROR_INVALIDCMDARGCONV)
            {
                snprintf(errbuf, sizeof(errbuf), "The value for %s must be a 15-bit positive integer.", kNewSuRetention);
                fprintf(stderr, errbuf);
            }

            snprintf(errbuf, sizeof(errbuf), "Invalid value for %s.", kNewSuRetention);
            fprintf(stderr, errbuf);
            return 1;
        }
        else if (newsuretention < 0)
        {
            snprintf(errbuf, sizeof(errbuf), "The value for %s must be a 15-bit positive integer.", kNewSuRetention);
            fprintf(stderr, errbuf);
            return 1;
        }
        else
        {
            newsuretention = (int16_t)(newsuretention & 0x7FFF);
        }
    }

  query_mem = 512;
  if (cmdparams_exists (&cmdparams, kQUERYMEMARG))
    query_mem = cmdparams_get_int (&cmdparams, kQUERYMEMARG, NULL);

  server_wait = 0;
  if (cmdparams_exists (&cmdparams, kSERVERWAITARG))
    server_wait = cmdparams_get_int (&cmdparams, kSERVERWAITARG, NULL);

    dbtimeout = INT_MIN;
    if (drms_cmdparams_exists(&cmdparams, kDBTimeOut))
    {
        dbtimeout = drms_cmdparams_get_int(&cmdparams, kDBTimeOut, NULL);
    }

    dbutf8clientencoding = 0;
    if (drms_cmdparams_exists(&cmdparams, kDBUtf8ClientEncoding))
    {
        dbutf8clientencoding = drms_cmdparams_get_int(&cmdparams, kDBUtf8ClientEncoding, NULL);
    }

    loopconn = cmdparams_isflagset(&cmdparams, kLoopConn);
    createshadows = cmdparams_isflagset(&cmdparams, kCreateShadows);
    print_sql_only = cmdparams_isflagset(&cmdparams, DRMS_ARG_PRINT_SQL);

  int fd[2];
  pid_t	pid;

    /* The pipe() sys call makes 2 file descriptors in each process. fd[0], which is present in both processes, can be read
     * from by both processes. fd[1] can be written to by both processes. In this case, we want the socket-module to read
     * from drms_server, so we want for the parent (socket module) to only read from the pipe, and we want the child (drms_server)
     * to write to only write to the pipe. So, we close the parent's write end of the pipe (fd[1]), and we close the child's
     * read end of the pipe (fd[0]).
     *
     * The select() sys call BLOCKs until one of the file descriptors in the set of file descriptors in readfd (which contains only
     * fd[0], the fd for reading from the pipe) is reading for reading from.
     */
  if (pipe(fd) < 0) {
    perror("pipe error");
    return -1;
  }

  if ( (pid = fork()) < 0) {
    perror("fork error");
    return -1;
  }
  else if (pid > 0) {	/* parent */
    close(fd[1]);	/* close write end */

    const int bufsz = 1024;
    char *server_info = 0, *line = 0;
    server_info = malloc(bufsz);
    XASSERT(server_info);
    line = malloc(bufsz);
    XASSERT(line);
    server_info[0] = '\0';
    int  n;
    fd_set readfd;
    do {
      FD_ZERO(&readfd);
      FD_SET(fd[0], &readfd);
      if (select(fd[0]+1, &readfd, NULL, NULL, NULL) < 0) {
	if (errno == EINTR)
	  continue;
	else
	{
	  perror("Select failed");
	  return -1;
	}
      }
      if ((n = read(fd[0], line, bufsz)) < 0) {
	perror("Read error from pipe");
	return -1;
      }
      if (n) {
	line[n] = '\0';
	if (strstr(line, "failed")) {
	  return -1;
	}
	strcat(server_info, line);
      }
/*       printf("%s\n-----\n", line); */
    } while (!strstr(line, "__ENDSELFSTART__"));
    if (verbose) {
      write(STDOUT_FILENO, server_info, strlen(server_info));
    }

    char *p = strstr(server_info, "DRMS_HOST");
    sscanf(p, "DRMS_HOST = %s", drms_host);
    p = strstr(server_info, "DRMS_PORT");
    sscanf(p, "DRMS_PORT = %s", drms_port);
    strcpy(drms_session, drms_host);
    strcat(drms_session, ":");
    strcat(drms_session, drms_port);
    //    setenv("DRMSSESSION", drms_session, 1);
    cmdparams_set(&cmdparams, "DRMSSESSION", drms_session);
    free(server_info);
    free(line);
    return pid;
  } else {						/* child */
    close(fd[0]);					/* close read end */

    if (fd[1] != STDOUT_FILENO) {
      if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
	perror ("dup2 error to stdout");
	exit (1);
      }
      close(fd[1]);
    }

    const int num_args = 20;
    char **argv = malloc(num_args*sizeof(char *));
    int i = 0;
    argv[i++] = strdup ("drms_server");
    argv[i++] = strdup ("-f");
    argv[i++] = strdup ("-b");
    if (verbose)
      argv[i++] = strdup ("-V");
    if (dolog)
      argv[i++] = strdup ("-L");
    argv[i] = malloc (strlen (dbHostAndPort)+DRMS_MAXNAMELEN);
    sprintf (argv[i++], "JSOC_DBHOST=%s", dbHostAndPort);
    argv[i] = malloc (strlen (dbname)+DRMS_MAXNAMELEN);
    sprintf (argv[i++], "JSOC_DBNAME=%s", dbname);
    if (dbuser) {
      argv[i] = malloc (strlen (dbuser)+DRMS_MAXNAMELEN);
      sprintf (argv[i++], "JSOC_DBUSER=%s", dbuser);
    }
    if (dbpasswd) {
      argv[i] = malloc (strlen (dbpasswd)+DRMS_MAXNAMELEN);
      sprintf(argv[i++], "JSOC_DBPASSWD=%s", dbpasswd);
    }
    if (sessionns) {
      argv[i] = malloc (strlen (sessionns)+DRMS_MAXNAMELEN);
      sprintf (argv[i++], "JSOC_SESSIONNS=%s", sessionns);
    }
    if (archive == -1 || archive == 0 || archive == 1) {
      argv[i] = malloc (DRMS_MAXNAMELEN*2);
      sprintf (argv[i++], "%s=%d", kARCHIVEARG, archive);
    }
    if (retention > 0) {
      argv[i] = malloc (DRMS_MAXNAMELEN*2);
      sprintf (argv[i++], "%s=%d", kRETENTIONARG, retention);
    }
    if (newsuretention > 0)
    {
        argv[i] = malloc(DRMS_MAXNAMELEN*2);
        snprintf(argv[i++], DRMS_MAXNAMELEN*2, "%s=%d", kNewSuRetention, newsuretention);
    }
    if (query_mem != 512) {
      argv[i] = malloc (DRMS_MAXNAMELEN*2);
      sprintf (argv[i++], "%s=%d", kQUERYMEMARG, query_mem);
    }
    if (!server_wait) {
      argv[i] = malloc (DRMS_MAXNAMELEN*2);
      sprintf (argv[i++], "%s=%d", kSERVERWAITARG, server_wait);
    }

      if (INT_MIN != dbtimeout)
      {
          argv[i] = malloc (DRMS_MAXNAMELEN*2);
          sprintf (argv[i++], "%s=%d", kDBTimeOut, dbtimeout);
      }

    if (loopconn)
    {
       char buf[256];

       snprintf(buf, sizeof(buf), "--%s", kLoopConn);
       argv[i++] = strdup(buf);
    }

      if (createshadows)
      {
          char buf[256];

          snprintf(buf, sizeof(buf), "--%s", kCreateShadows);
          argv[i++] = strdup(buf);
      }

      if (dbutf8clientencoding)
      {
          argv[i] = malloc(DRMS_MAXNAMELEN * 2);
          snprintf(argv[i++], DRMS_MAXNAMELEN * 2, "%s=1", kDBUtf8ClientEncoding);
      }

      if (print_sql_only)
      {
          char buf[256];

          argv[i] = malloc(DRMS_MAXNAMELEN * 2);
          snprintf(argv[i++], DRMS_MAXNAMELEN * 2, "%s=1", DRMS_ARG_PRINT_SQL);
      }

    for (; i < num_args; i++) {
      argv[i] = NULL;
    }

      if (verbose)
      {
          fprintf(stderr, "Calling drms_server with args:\n");

          for (i = 0; i < num_args; i++)
          {
              fprintf(stderr, "\t%s\n", argv[i]);
          }
      }

    if (execvp ("drms_server", argv) < 0) {
      printf ("drms_start_server failed to start server.\n");
      perror ("exec error for drms_server");
      exit (1);
    }
  }

  if (verbose) {
    if (!dolog) printf ("Log Files not copied to DRMS_SUDIR\n");
    printf ("Starting command now.\n");
  }

  return(0);

}
