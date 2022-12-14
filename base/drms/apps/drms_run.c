#include <sys/wait.h>
#include <pthread.h>
#include "jsoc.h"
#include "cmdparams.h"
#include "timer.h"
#include "util.h"

/**
@defgroup drmsrun drms_run - Run a DRMS module and connect it to a running DRMS server application (drms_server)
@ingroup a_programs

@brief This program executes all the commands in the provided script in a single DRMS session.

@par Synopsis:
@code
drms_run <drms_run script> [ <unnamed argument2> [ <unnamed argument3> [ ... ] ] ]
           [ to=<time out> ] [ DRMS_RETENTION=<days> ] [ drmslog=<drms_server log path> ] [ drmsrunlog=<output log>]
           [ server=<path to server> ]
           [ -d ] [ -L ] [ -V | -v | --verbose ]
@endcode

This program takes as input a script and script arguments and executes the script with its arguments
inside a DRMS session. As a result, when the state of the DRMS database is changed by a script command,
the command that follows will 'see' the changes in the DRMS database. This is not true for programs
running outside the DRMS session (in a separate DRMS session). They cannot 'see' any changes
until the first DRMS session terminates. In this way, the commands of the input script can make 
database changes in concert 
without making those changes available to programs running outside the DRMS session. After the last
script command is run, drms_run ends the DRMS session. At that time all database changes are committed
and made available to programs running in all subsequent DRMS sessions.

As a consequence of this design, drms_run is most useful for implementing DRMS pipelines. All the 
commands necessary to convert the pipeline input
to the pipeline output are placed into a drms_run script. Should an error occur anywhere in the pipeline, 
the drms_run script can trap that error and exit with a non-zero value. This will cause the DRMS session
to abort, and no changes will be propagated to the database. Also, if an individual script command is a 
DRMS module, it can return a non-zero value, and this will also cause the DRMS session to abort and terminate.

drms_run starts a drms_server application, which in turn opens a connection to the DRMS database and starts
a DRMS session. Commands that interact with the database (generally DRMS modules) do so by sending 
requests over a socket connection to drms_server, which then communicates directly with the database.
In order for a module to run inside the DRMS session started by drms_run, it must be a 'sock' module (a 
sockect-connect module), and not a direct-connect module. Socket-connect-module names all contain the
"_sock" suffix (e.g., show_info_sock). Such modules scan the environment for special environment variables
that tell the module how to locate a specific drms_server instance. Therefore, in order for a sock module 
to connect to a particular drms_server
instance, these special environment variables must be set with parameters specific to the drms_server 
of interest. drms_run achieves this by capturing the parameters which are generated by drms_server. 
drms_run obtains the parameters by starting drms_server with the 'shenvfile' argument. This argument 
provides a file path to which drms_server will write a bash-style source file that will
set all the relevant environment variables necessary for the sock modules to locate and connect to 
the drms_server instance. drms_run sources this file before running the drms_run script, which ensures
the sock modules contained within the drms_run script will use the drms_server, and hence DRMS session,
started by drms_run.

Direct-connect modules do not have the "_sock" suffix (e.g., show_info). Should a drms_run script
contain a direct-connect module command, that module will connect to the DRMS database via a 
new DRMS session and it will not be part of the DRMS session created by drms_run. This is perfectly
legitimate and appropriate for certain types of pipeline processing.

@par PARAMETERS:
@param @c UNNAMED1 The first unnamed argument is the path to the drms_run script 
@param @c UNNAMED2 The second unnamed argument is the first argument to the drms_run script
@param @c UNNAMEDN The Nth unnamed argument is the (N-1)st argument to the drms_run script
@param @c to The timeout, in seconds, relevant when this program is waiting for drms_server to produce
the environment file
@param @c DRMS_RETENTION As the drms_run script executes, it might access SUMS Storage Units - for each
such Storage Unit, this program will set the retention time to the value of this argument (in days) if 
the current retention time of the SU is less than the value of this argument.
@param @c drmslog The DIRECTORY to which a file named drmsserver_<pid>.log will be written. 
The file will contain the stdout and stderr from the instantiated drms_server (<pid> is the pid of 
the drms_server process). This log will also be copied to the drms_server log directory if the -L flag
is set.
@param @c drmsrunlog The DIRECTORY to which a file named drmsrun_<pid>.log will be written. The file
will contain the stdout and stderr from the drms_run program. (<pid> is the pid of 
the drms_server process).

@par FLAGS:
@c -d The drms_run script will be deleted immediately prior to termination.
@c -L drms_server will be started with the -L flag, and the drms_server output will be 
copied to the DRMS session log directory.
@c -V Run verbosely
@c -v Run verbosely
@c --verbose Run verbosely

@par GEN_FLAGS:
Ubiquitous flags present in every module.
@ref jsoc_main

@par Exit_Status:
@c -2 invalid arguments<br>
@c -1 user requested the help screen<br>
@c 0 drms_server committed upon exiting<br>
@c 1 drms_server aborted upon exiting (there was an error)<br>
@c 2 failed to run script with DRMS commands<br>
@c 3 failed to send kill signal to drms_server<br>
@c 4 drms_server failed to shut down properly<br>
@c 5  couldn't find drms_server env file (perhaps not written)<br>


@par Example:

@code
drms_run drmslog=/tmp/arta drmsrunlog=/tmp/arta -L poke_missing.csh ds=mdi.fd_V_lev18test key=T_REC start=10 count=100
@endcode
*/

#define kDRMSSERVERLOG "drmslog"
#define kDRMSSERVERLOGDEF "/tmp"
#define kDRMSRUNLOG "drmsrunlog"
#define kSERVER "server"
#define kNOTSPECIFIED "notspecified"

#define kDELSCRIPTFLAG "d"
#define kVERBOSEFLAGA "v"
#define kVERBOSEFLAGB "V"
#define kVERBOSEFLAGC "verbose"
#define kDOLOGFLAG "L"
#define kDRMSERVERENV "/tmp/drms_server_env"
#define kTIMEOUT "to"
#define kTIMEOUTDEF "15"
#define kRETENTION "DRMS_RETENTION"
#define kRETENTIONDEF "NoTsPeCiFiED"
#define kNEWSURETENTION "DRMS_NEWSURETENTION"
#define kNEWSURETENTIONDEF "NoTsPeCiFiED"


enum RUNstat_enum
{
   kSTAT_SIGTHREAD = -7,
   kSTAT_SIGMASK = -6,
   kSTAT_MUTEX = -5,
   kSTAT_DRMSSERVERWONTSTART = -4,
   kSTAT_TERMINATE = -3,           /* drms_runs has received a SIGINT signal */
   kSTAT_ARGERROR = -2,
   kSTAT_HELP = -1,
   kSTAT_COMMIT = 0,               /* drms_server committed upon exiting */
   kSTAT_ABORT = 1,                /* drms_server aborted upon exiting (there was an error) */
   kSTAT_SCRIPTFAILURE =   2,      /* failed to run script with DRMS commands */
   kSTAT_KILLFAILED = 3,           /* failed to send kill signal to drms_server */
   kSTAT_DRMSSERVERFAILURE = 4,    /* drms_server failed to shut down properly */
   kSTAT_ENVTIMEOUT = 5            /* couldn't find drms_server env file (perhaps not written) */
};

typedef enum RUNstat_enum RUNstat_enum_t;

ModuleArgs_t module_args[] = 
{
   /* Don't put unnamed arguments in module_args - otherwise cmdparams_parse() will expect them
    * {ARG_STRING, kSCRIPT, NULL, "The script to run - contains socket-module cmds."}, 
    */
   {ARG_STRING, kDRMSSERVERLOG, kDRMSSERVERLOGDEF, "The path to the drms_server log files."},
   {ARG_STRING, kDRMSRUNLOG, kNOTSPECIFIED, "The path to the drms_run log files."},
   {ARG_STRING, kSERVER, "drms_server", "The path to the drms_server to run."},
   {ARG_DOUBLE, kTIMEOUT, kTIMEOUTDEF, "Time limit, in seconds, to find drms_server's environment file."},
   {ARG_STRING, kRETENTION, kRETENTIONDEF, "Minimum retention, in days, for all SUs fetched during DRMS session."},
   {ARG_STRING, kNEWSURETENTION, kNEWSURETENTIONDEF, "Retention, in days, for all SUs created during DRMS session."},
   {ARG_FLAG, kDELSCRIPTFLAG, NULL, "Indicates that the script file should be deleted after use."},
   {ARG_FLAG, kVERBOSEFLAGA, NULL, "Print diagnostic messages."},
   {ARG_FLAG, kVERBOSEFLAGB, NULL, "Print diagnostic messages."},
   {ARG_FLAG, kVERBOSEFLAGC, NULL, "Print diagnostic messages."},
   {ARG_FLAG, kDOLOGFLAG, NULL, "Write drms_server output to a logfile in an SUDIR."},
   {ARG_END}
};

ModuleArgs_t *gModArgs = module_args;

/* Global structure holding command line parameters. */
CmdParams_t cmdparams;

static int gTerminate = 0;
static pthread_mutex_t gSiglock;
static pthread_t gSigthreadid;

static int TerminationTime()
{
   int rv = 0;

   pthread_mutex_lock(&gSiglock);
   rv = (gTerminate == 1);
   pthread_mutex_unlock(&gSiglock);

   return rv;
}

static void SetTerminate(int val)
{
   pthread_mutex_lock(&gSiglock);
   gTerminate = val;
   pthread_mutex_unlock(&gSiglock);
}

/* Must have a SIGINT signal handler since we will regularly ctrl-c drms_run. This handle needs to
 * set a flag so that clean-up code runs. In particular, we need to ensure that drms_server is terminated.
 * If the drms_run script, which is executed with a system() call, is being executed when
 * drms_run receives a SIGINT, then ctrl-c will be ignored by drms_run (the system() call
 * blocks SIGINT). The SIGINT signal will be passed to the drms_run script. 
 * The drms_run script itself will pass the SIGINT to whatever child is currently running, 
 * then it will terminate itself, returning a SIGINT from the system() call that launched it. Accordingly,
 * drms_run must check the return value from system() and if the drms_run
 * script terminated because it received a SIGINT signal, drms_run must clean-up and abort.
 */
void *sigthread(void *arg)
{
   int status;
   int signo;
   sigset_t *sigmask = (sigset_t *)arg;

   /* must block SIGINT before actually waiting for it */
   if((status = pthread_sigmask(SIG_BLOCK, sigmask, NULL)))
   {
      fprintf(stderr, "pthread_sigmask call failed with status = %d\n", status);
      fprintf(stderr, "Unable to initialize signal thread.\n");
      return NULL;
   }

   while (1)
   {
      if ((status = sigwait(sigmask, &signo)) != 0)
      {
         if (status != EINTR)
         {
            fprintf(stderr,"sigwait error, errcode=%d.\n",status);
            break;
         }
      }

      if (signo == SIGUSR1)
      {
         break;
      }
      else if (signo == SIGINT)
      {
         /* Set flag denoting termination, and kill signal thread. */
         SetTerminate(1);
         break;
      }
   }

   /* fprintf(stderr,"signal thread terminating.\n"); */
   return NULL;
}

static void DRMSrunExit(int status)
{
   pthread_kill(gSigthreadid, SIGUSR1); /* may fail if signal thread has already terminated, but that is
                                         * OK. */
   pthread_join(gSigthreadid, NULL);
   pthread_mutex_destroy(&gSiglock);
   exit(status);
}

/* takes a single parameter - a script to run */
int main(int argc, char *argv[])
{
   pid_t pid = 0;
   pid_t pidret = 0;
   char envfile[PATH_MAX];
   char cmd[PATH_MAX];
   const char *script = NULL;
   const char *serverlog = NULL;
   const char *server = NULL;
   const char *drmsrunlog = NULL;
   double timeout = 15;
   int delscr = 0;
   int verbose = 0;
   int dolog = 0;
   int abort = 0;
   float elapsed = 0;
   struct stat stbuf;
   int status = 0;
   RUNstat_enum_t runstat = kSTAT_COMMIT;
   char *passargs = NULL;
   size_t szpassargs = 0;
   const char *argcmdlinestr = NULL;
   int argacc = 0;
   int iarg = 0;

   /* set up ctrl-c signal handler */
   sigset_t sigmask;
   sigemptyset(&sigmask);
   sigaddset(&sigmask, SIGINT);
   sigaddset(&sigmask, SIGUSR1);

   /* intialize signal lock */
   if ((status = pthread_mutex_init(&gSiglock, NULL)) != 0)
   {
      fprintf(stderr, "pthread_mutex_init call failed with status = %d\n", status);
      exit(kSTAT_MUTEX);
   }

   /* block the SIGINT signal */
   if ((status = pthread_sigmask(SIG_BLOCK, &sigmask, NULL)) != 0)
   {
      fprintf(stderr, "pthread_sigmask call failed with status = %d\n", status);
      pthread_mutex_destroy(&gSiglock);
      exit(kSTAT_SIGMASK);
   }

   /* create the signal thread */
   if((status = pthread_create(&gSigthreadid, NULL, &sigthread, (void *)&sigmask)) != 0)
   {
      fprintf(stderr,"Signal-thread creation failed: %d\n", status);          
      DRMSrunExit(kSTAT_SIGTHREAD);
   }

   if ((status = cmdparams_parse(&cmdparams, argc, argv)) == -1)
   {
      fprintf(stderr,"Error: Command line parsing failed. Aborting.\n");
      DRMSrunExit(kSTAT_ARGERROR);
   }
   else if (status == CMDPARAMS_QUERYMODE)
   {
       cmdparams_usage(argv[0]);
       DRMSrunExit(kSTAT_HELP);
   }
   else if (status == CMDPARAMS_NODEFAULT)
   {
      fprintf(stderr, "For usage, type %s [-H|--help]\n", argv[0]);
      DRMSrunExit(kSTAT_ARGERROR);
   }

   if (TerminationTime())
   {
      DRMSrunExit(kSTAT_TERMINATE);
   }

   script = cmdparams_getarg(&cmdparams, 1);
   serverlog = cmdparams_get_str(&cmdparams, kDRMSSERVERLOG, NULL);
   drmsrunlog = cmdparams_get_str(&cmdparams, kDRMSRUNLOG, NULL);
   server = cmdparams_get_str(&cmdparams, kSERVER, NULL);
   timeout = cmdparams_get_double(&cmdparams, kTIMEOUT, NULL);
   delscr = cmdparams_isflagset(&cmdparams, kDELSCRIPTFLAG);
   verbose = (cmdparams_isflagset(&cmdparams, kVERBOSEFLAGA) ||
              cmdparams_isflagset(&cmdparams, kVERBOSEFLAGB) ||
              cmdparams_isflagset(&cmdparams, kVERBOSEFLAGC));
   dolog = cmdparams_isflagset(&cmdparams, kDOLOGFLAG);

   /* Need to pass on any unused arguments to script - iterate through cmdparams */
   szpassargs = 32;
   passargs = malloc(sizeof(char) * szpassargs);

   while (cmdparams_getargument(&cmdparams, iarg, NULL, NULL, &argcmdlinestr, &argacc))
   {
      if (!argacc && argcmdlinestr)
      {
         passargs = base_strcatalloc(passargs, argcmdlinestr, &szpassargs);
         passargs = base_strcatalloc(passargs, " ", &szpassargs);
      }

      iarg++;
   }

   if (TerminationTime())
   {
      DRMSrunExit(kSTAT_TERMINATE);
   }

   if ((pid = fork()) == -1)
   {
      /* parent - couldn't start child process */
      pid = getpid();
      fprintf(stderr, "Failed to start drms_server.\n");
      runstat = kSTAT_DRMSSERVERWONTSTART;
   }
   else if (pid > 0)
   {
      /* parent - pid is child's (drms_server's) pid */
      FILE *fptr = NULL;
      FILE *actstdout = stdout;
      FILE *actstderr = stderr;
      FILE *efptr = NULL;
      char sulogdir[PATH_MAX];
      char logfile[PATH_MAX];
      int waitforit = 0;

      if (strcmp(drmsrunlog, kNOTSPECIFIED) != 0)
      {
         snprintf(logfile, sizeof(logfile), "%s/drmsrun_%llu.log", drmsrunlog, (unsigned long long)pid);
         fptr = fopen(logfile, "w");
      }

      if (fptr)
      {
         actstdout = fptr;
         actstderr = fptr;
      }

      if (verbose)
      {
         fprintf(actstdout, "Loading environment for drms_server pid %llu.\n", (unsigned long long)pid);
      }

      snprintf(envfile, sizeof(envfile), "%s.%llu", kDRMSERVERENV, (unsigned long long)pid);
      
      if (verbose)
      {
         time_t now;
         time(&now);
         fprintf(actstdout, "Start looking for environment file %s at %s\n", envfile, ctime(&now));
      }

      /* wait for server env file to appear */
      StartTimer(25);

      while (1)
      {
         elapsed = StopTimer(25);
         if (elapsed > timeout)
         {
            runstat = kSTAT_ENVTIMEOUT;
            abort = 1;
            
            fprintf(actstderr, 
                    "Time out - couldn't find environment file for drms_server pid %llu.\n", 
                    (unsigned long long)pid);

            break;
         }

         if (!stat(envfile, &stbuf) && S_ISREG(stbuf.st_mode))
         {
            if (verbose)
            {
               fprintf(actstdout, "Found environment file for drms_server pid %llu.\n", (unsigned long long)pid);
            }

            break;
         }

         sleep(1);
      }

      if (TerminationTime())
      {
         runstat = kSTAT_TERMINATE;
         abort = 1;
      }

      if (runstat == kSTAT_COMMIT)
      {
         *sulogdir = '\0';

         if (dolog)
         {
            /* Must read environment file to get the SU of the log directory */
            efptr = fopen(envfile, "r");

            if (efptr)
            {
               char *psudir = NULL;
               char line[LINE_MAX];
               char *end = NULL;

               while (fgets(line, LINE_MAX, efptr) != NULL)
               {
                  if (strstr(line, "DRMS_SUDIR="))
                  {
                     if ((psudir = strchr(line, '/')) != NULL)
                     {
                        end = strchr(line, ';');
                        if (end)
                        {
                           *end = '\0';
                        }
                        snprintf(sulogdir, sizeof(sulogdir), "%s", psudir);
                     }

                     break;
                  }
               }

               fclose(efptr);
            }
         }

         /* The server env file is available - source it and run script.
          * script must figure out if a failure happened or not, and
          * then return 0 (commit) or non-0 (abort) */
         snprintf(cmd, sizeof(cmd), "source %s; %s %s", envfile, script, passargs);
         if (verbose)
         {
            fprintf(actstdout, "Running cmd '%s' on drms_server pid %llu.\n", cmd, (unsigned long long)pid);
         }

         if (TerminationTime())
         {
            runstat = kSTAT_TERMINATE;
            abort = 1;
         }
         else
         {
            status = system(cmd);      

            if (status == -1)
            {
               runstat = kSTAT_SCRIPTFAILURE;
               abort = 1;
               fprintf(actstderr, "Could not execute '%s' properly; bailing.\n", script);
            }
            else if (WIFEXITED(status) && WEXITSTATUS(status))
            {
               /* I don't know if this is the right way to read this return value - the man pages 
                * about this are horrible. */
               if ((WEXITSTATUS(status) & 0x7F) == SIGINT)
               {
                  /* If drms_run received a SIGINT signal during the system() call, then the system() call
                   * that launched the drms_run script will return a SIGINT. */
                  SetTerminate(1);
                  runstat = kSTAT_TERMINATE;
                  abort = 1;
               }
               else
               {
                  /* socket modules will return non-zero (doesn't have to be 1) to indicate 
                   * abort should happen */
                  /* Script requests abort - abort */
                  runstat = kSTAT_ABORT;
                  abort = 1;
               }
            }
         }
      }
     
      if (verbose)
      {
         fprintf(actstdout, "About to kill drms_server pid %llu.\n", (unsigned long long)pid);
      }

      /* copy drms log file into SU if there was no error; if socket-connect
       * module called abort, drms_server may have already terminated, which
       * would cause the SUM_put() to have been called, which would make the
       * log SU unwritable. */
      if (runstat == kSTAT_COMMIT && dolog && *sulogdir)
      {
         /* copy log file to log directory */
         char sulogfile[PATH_MAX];
         int ioerr;

         snprintf(logfile, sizeof(logfile), "%s/drmsserver_%llu.log", serverlog, (unsigned long long)pid);
         snprintf(sulogfile, sizeof(sulogfile), "%s/command.txt", sulogdir);

         if (!stat(logfile, &stbuf))
         {
            if (CopyFile(logfile, sulogfile, &ioerr) != stbuf.st_size)
            {
               fprintf(stderr, "Failed to copy drms log file to log-file SU.\n");
            }
         }
      }

      waitforit = 0;
      if (abort)
      {
         char proclink[PATH_MAX];
         char ppath[PATH_MAX];

         snprintf(proclink, sizeof(proclink), "/proc/%i/exe", pid);

         if (runstat == kSTAT_ABORT)
         {
            /* If a client socket-connect modules sets the abort flag, this will 
             * send a SIGTERM signal to drms_server. In that case, there is no need
             * to resend the signal here. But, just to make sure, if drms_server 
             * has not shutdown, send it again. */
            int nx;

            nx = 0; /* try 5 times at most */
            while (nx < 5 && (readlink(proclink, ppath, sizeof(ppath)) != -1))
            {
               /* drms_server still there*/
               sleep(1);
               nx++;
            }
         }

         if (readlink(proclink, ppath, sizeof(ppath)) != -1)
         {
            kill(pid, SIGTERM);
            waitforit = 1;
         }
      }
      else
      {
         kill(pid, SIGUSR1);
         waitforit = 1;
      }

      if (waitforit)
      {
         pidret = waitpid(pid, &status, 0);

         if (pidret != pid)
         {
            fprintf(actstderr, "pid of killed drms_server does not match pid in kill syscall.\n");
            runstat = kSTAT_KILLFAILED;
         }
         else if (WIFEXITED(status))
         {
            /* drms_server returned non-zero value */
            /* If drms_server was told to abort, then it returns 1. If it was told to commit, 
             * then it returns 0. */
            if (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 1)
            {
               /* drms_server did not return commit (1) or abort (0) */
               fprintf(actstderr, 
                       "drms_server failed to shut down properly, returned '%d'.\n", 
                       (int)WEXITSTATUS(status));
               runstat = kSTAT_DRMSSERVERFAILURE;
            }
         }
      }

      /* clean up env file */
      unlink(envfile);

      if (delscr)
      {
         unlink(script);
      }

      DRMSrunExit(runstat);
   }
   else
   {
      /* child */
      if (passargs)
      {
         free(passargs);
      }

      pid = getpid();
      char logfile[PATH_MAX];
      char tmp[128] = {0};
      int fd;
      const char *retention = NULL;
      const char *newsuretention = NULL;
      char **drmsargs = NULL;

      snprintf(logfile, 
               sizeof(logfile), 
               "%s/drmsserver_%llu.log", 
               serverlog, 
               (unsigned long long)pid);

      drmsargs = (char **)calloc(128, sizeof(char *));

      iarg = 0;
      drmsargs[iarg++] = strdup(server);
      drmsargs[iarg++] = strdup("-f");

      if (verbose)
      {
         drmsargs[iarg++] = strdup("-V");
      }

      if (dolog)
      {
         drmsargs[iarg++] = strdup("-L");
      }

      snprintf(tmp, sizeof(tmp), "shenvfile=%s", kDRMSERVERENV);
      drmsargs[iarg++] = strdup(tmp);

      /* An operator cannot specify an SU retention for socket-connect modules that do 
       * not self-start a drms_server - retention can be specified for drms_server and 
       * other server apps only. To specify a retention time, the DRMS_RETENTION
       * cmd-line arg must be provided. If drms_server is started without DRMS_RETENTION specified,
       * then the retention value specified in the jsd of the SU's owning series is used. The retention
       * for the drms_server logfile itself, however, comes from the DRMS_RETENTION cmd-line argument,
       * if it is specified. If the cmd-line parameter is not specified, then a default value is
       * used (the DRMS_LOG_RETENTION #define, which is currently set to 10).
       *
       * At present, there is no way to turn off logging of the drms_server logfile.
       * Since many socket-connect modules could connect to the same drms_server,
       * there is no way to know when the server has started whether saving of the
       * log file will be needed or not, so saving of the log is always enabled.
       *
       * So, if the caller of this script provides a DRMS_RETENTION cmd-line argument, this
       * will be passed to drms_server, which will cause all SU dirs created and fetched
       * to have the passed-in value. And this will cause the drms_server log to also have
       * the same retention value.
       */
      retention = cmdparams_get_str(&cmdparams, kRETENTION, NULL);
      if (strcmp(retention, kRETENTIONDEF) != 0)
      {
         snprintf(tmp, sizeof(tmp), "DRMS_RETENTION=%s", retention);
         drmsargs[iarg++] = strdup(tmp);
      }
       
      newsuretention = cmdparams_get_str(&cmdparams, kNEWSURETENTION, NULL);
      if (strcmp(newsuretention, kNEWSURETENTIONDEF) != 0)
      {
          snprintf(tmp, sizeof(tmp), "DRMS_NEWSURETENTION=%s", newsuretention);
          drmsargs[iarg++] = strdup(tmp);
      }

      fd = open(logfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
      dup2(fd, 1);
      dup2(1, 2);

      /* If you use execlp, then the call would look something like 
       * execlp("drms_server", "drms_server", "-f", arg, (char *)0);
       */
      execvp(server, drmsargs);

      /* does not return */
   }

   if (passargs)
   {
      free(passargs);
   }

   DRMSrunExit(runstat);
}
