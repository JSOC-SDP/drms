#!/usr/bin/env python

import sys

if sys.version_info < (3, 4):
    raise Exception("you must run the 3.4 release, or a more recent release, of Python")

import os
import pwd
import logging
import time
from datetime import datetime, timedelta
import argparse
import signal
import psycopg2
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../../include'))
from drmsparams import DRMSParams
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../libs/py'))
from drmsCmdl import CmdlParser
from drmsLock import DrmsLock


# return code
RV_SUCCESS = 0
RV_INITIALIZATION = 1
RV_DRMSPARAMS = 2
RV_ARGS = 3
RV_LOG_INITIALIZATION = 4
RV_DBCONNECTION = 5
RV_DBCOMMAND = 6
RV_DBCOMMAND_RESULT = 7
RV_TERMINATED = 8

class RsumsDrmsParams(DRMSParams):

    def __init__(self):
        super(RsumsDrmsParams, self).__init__()

    def get(self, name):
        val = super(RsumsDrmsParams, self).get(name)

        if val is None:
            raise ParamsException('unknown DRMS parameter: ' + name + '.')
        return val


def terminator(*args):
    # Raise the SystemExit exception (which will be caught by the __exit__() method below).
    sys.exit(0)

class TerminationHandler(object):
    class Break(Exception):
        """break out of the TerminationHandler context block"""

    def __new__(cls, thContainer):
        return super(TerminationHandler, cls).__new__(cls)

    def __init__(self, thContainer):
        self.container = thContainer
        arguments = thContainer[0]
        self.pidStr = thContainer[1]
        self.log = thContainer[2]
        
        self.lockFile = os.path.join(arguments.DRMS_LOCK_DIR, 'rsums-client.lck')

        self.dbname = arguments.dbdatabase
        self.dbuser = arguments.dbuser
        self.dbhost = arguments.dbhost
        self.dbport = arguments.dbport
        
        self.dbnameSums = self.dbname + '_sums'
        self.dbuserSums = arguments.SUMS_READONLY_DB_USER # connect to SUMS as SUMS_READONLY_DB_USER user
        self.dbhostSums = arguments.SUMS_DB_HOST
        self.dbportSums = arguments.SUMPGPORT
        
        self.conn = None
        self.connSums = None
        
        super(TerminationHandler, self).__init__()
        
    def __enter__(self):
        signal.signal(signal.SIGINT, terminator)
        signal.signal(signal.SIGTERM, terminator)
        signal.signal(signal.SIGHUP, terminator)

        # Acquire locks.
        self.rsLock = DrmsLock(self.lockFile, self.pidStr)
        self.rsLock.acquireLock()
        
        # Make main DB connection to RS database. We also have to connect to the SUMS database, so connect to that too.
        # The connections are NOT in autocommit mode. If changes need to be saved, then conn.commit() must be called.
        # Do this instead of using BEGIN and END/COMMIT statements, cuz I don't know if the psycopg2/libpq interaction
        # supports this properly.
        try:
            self.openRsConn()            
            self.openRsConnSums()
        except DBConnectionException() as exc:
            self.log.writeError([ exc.args[0] ])
            self.__exit__(*sys.exc_info()) # try cleaning up (will return False since this is not a self.Break)            
            raise InitializationException('failure initializing client instance')
        except:
            raise InitializationException('failure initializing client instance')

        return self

    # Normally, __exit__ is called if an exception occurs inside the with block. And since SIGINT is converted
    # into a KeyboardInterrupt exception, it will be handled by __exit__(). However, SIGTERM will not - 
    # __exit__() will be bypassed if a SIGTERM signal is received. Use the signal handler installed in the
    # __enter__() call to handle SIGTERM.
    def __exit__(self, etype, value, traceback):
        if etype is not None:
            # If the context manager was exited without an exception, then etype is None
            import traceback
            self.log.writeDebug([ traceback.format_exc(5) ])
                            
        if etype == SystemExit:
            self.log.writeInfo([ 'termination signal handler called' ])
            self.container[3] = RV_TERMINATED

        self.finalStuff()
        
        # Clean up lock
        try:     
            self.rsLock.releaseLock()   
            self.rsLock.close()
            self.rsLock = None
        except IOError:
            pass
            
        self.log.writeDebug([ 'exiting TerminationHandler' ])
        
        if etype == self.Break:
            self.log.writeInfo([ 'completed generating set-up script' ])
            self.container[3] = RV_SUCCESS
            return True
        
    def finalStuff(self):
        self.log.writeInfo([ 'closing DB connections' ])
        self.closeRsConnSums()
        self.closeRsConn()
    
        self.log.writeInfo([ 'terminating logging' ])
        self.log.flush()

    def closeRsConn(self, commit=True):
        if self.conn:
            if commit:
                self.conn.commit()
            else:
                self.conn.rollback()
            
            self.conn.close()
            self.conn = None
    
    def closeRsConnSums(self, commit=True):
        if self.connSums:
            if commit:
                self.connSums.commit()
            else:
                self.connSums.rollback()
            self.connSums.close()
            self.connSums = None
    
    def openRsConn(self):
        if self.conn:
            raise DBConnectionException('cannot open DRMS database connection; connection already exists')
        
        try:
            self.conn = psycopg2.connect(database=self.dbname, user=self.dbuser, host=self.dbhost, port=self.dbport)
            self.log.writeInfo([ 'connected to DRMS database ' + self.dbname + ' on ' + self.dbhost + ':' + str(self.dbport) + ' as user ' + self.dbuser ])
        except psycopg2.DatabaseError as exc:
            self.closeRsConn()
            self.container[3] = RV_DBCONNECTION
            raise DBConnectionException('unable to connect to DRMS database')
        except psycopg2.Error as exc:
            self.closeRsConn()
            self.container[3] = RV_DBCOMMAND
            raise DBConnectionException(exc.diag.message_primary)

    def openRsConnSums(self):
        if self.connSums:
            raise DBConnectionException('cannot open SUMS database connection; connection already exists')

        try:
            self.connSums = psycopg2.connect(database=self.dbnameSums, user=self.dbuserSums, host=self.dbhostSums, port=self.dbportSums)
            self.log.writeInfo([ 'connected to SUMS database (read-only)' + self.dbnameSums + ' on ' + self.dbhostSums + ':' + str(self.dbportSums) + ' as user ' + self.dbuserSums ])
        except psycopg2.DatabaseError as exc:
            self.closeRsConnSums()
            self.container[3] = RV_DBCONNECTION
            raise DBConnectionException('unable to connect to SUMS database')
        except psycopg2.Error as exc:
            self.closeRsConnSums()
            self.container[3] = RV_DBCOMMAND
            raise DBConnectionException(exc.diag.message_primary)
        

    def rsConn(self):
        return self.conn
        
    def rsConnSums(self):
        return self.connSums


class Arguments(object):

    def __init__(self, parser):
        # This could raise in a few places. Let the caller handle these exceptions.
        self.parser = parser
        
        # Parse the arguments.
        self.parse()
        
        # Set all args.
        self.setAllArgs()
        
    def parse(self):
        try:
            self.parsedArgs = self.parser.parse_args()      
        except Exception as exc:
            if len(exc.args) == 2:
                type, msg = exc
                  
                if type != 'CmdlParser-ArgUnrecognized' and type != 'CmdlParser-ArgBadformat':
                    raise # Re-raise

                raise ArgsException(msg)
            else:
                raise # Re-raise

    def setArg(self, name, value):
        if not hasattr(self, name):
            # Since Arguments is a new-style class, it has a __dict__, so we can
            # set attributes directly in the Arguments instance.
            setattr(self, name, value)
        else:
            raise ArgsException('attempt to set an argument that already exists: ' + name)
            
    def set(self, name, value):
        # Sets attribute, even if it exists already.
        setattr(self, name, value)

    def setAllArgs(self):
        for key,val in list(vars(self.parsedArgs).items()):
            self.setArg(key, val)

    def setDictArgs(self, dict):
        for key, val in dict.items():
            self.setArg(key, val)
        
    def getArg(self, name):
        try:
            return getattr(self, name)
        except AttributeError as exc:
            raise ArgsException('unknown argument: ' + name + '.')
            
    def get(self, name):
        # None is returned if the argument does not exist.
        return getattr(self, name, None)            

    def dump(self, log):
        attrList = []
        for attr in sorted(vars(self)):
            attrList.append('  ' + attr + ':' + str(getattr(self, attr)))
        log.writeDebug([ '\n'.join(attrList) ])

 
class Log(object):
    """Manage a logfile."""
    def __init__(self, file, level, formatter):
        self.fileName = file
        self.log = logging.getLogger()
        self.log.setLevel(level)
        self.fileHandler = logging.FileHandler(file)
        self.fileHandler.setLevel(level)
        self.fileHandler.setFormatter(formatter)
        self.log.addHandler(self.fileHandler)
        
    def close(self):
        if self.log:
            if self.fileHandler:
                self.log.removeHandler(self.fileHandler)
                self.fileHandler.flush()
                self.fileHandler.close()
                self.fileHandler = None
            self.log = None
            
    def flush(self):
        if self.log and self.fileHandler:
            self.fileHandler.flush()
            
    def getLevel(self):
        # Hacky way to get the level - make a dummy LogRecord
        logRecord = self.log.makeRecord(self.log.name, self.log.getEffectiveLevel(), None, '', '', None, None)
        return logRecord.levelname

    def writeDebug(self, text):
        if self.log:
            for line in text:
                self.log.debug(line)
            self.fileHandler.flush()
            
    def writeInfo(self, text):
        if self.log:
            for line in text:
                self.log.info(line)
        self.fileHandler.flush()
    
    def writeWarning(self, text):
        if self.log:
            for line in text:
                self.log.warning(line)
            self.fileHandler.flush()
    
    def writeError(self, text):
        if self.log:
            for line in text:
                self.log.error(line)
            self.fileHandler.flush()
            
    def writeCritical(self, text):
        if self.log:
            for line in text:
                self.log.critical(line)
            self.fileHandler.flush()


class RSException(Exception):

    def __init__(self, msg):
        super(RSException, self).__init__(msg)

class InitializationException(RSException):

     def __init__(self, msg):
        super(InitializationException, self).__init__(msg)
        self.rv = RV_INITIALIZATION

class ParamsException(RSException):

    def __init__(self, msg):
        super(ParamsException, self).__init__(msg)
        self.rv = RV_DRMSPARAMS

class ArgsException(RSException):

    def __init__(self, msg):
        super(ArgsException, self).__init__(msg)
        self.rv = RV_ARGS

class LogException(RSException):

    def __init__(self, msg):
        super(LogException, self).__init__(msg)
        self.rv = RV_LOG_INITIALIZATION
        
class DBConnectionException(RSException):

    def __init__(self, msg):
        super(DBConnectionException, self).__init__(msg)
        self.rv = RV_DBCONNECTION

class DBCommandException(RSException):

    def __init__(self, msg):
        super(DBCommandException, self).__init__(msg)
        self.rv = RV_DBCOMMAND

class DBCommandResultException(RSException):

    def __init__(self, msg):
        super(DBCommandResultException, self).__init__(msg)
        self.rv = RV_DBCOMMAND_RESULT

class LogLevelAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        valueLower = value.lower()
        if valueLower == 'critical':
            level = logging.CRITICAL
        elif valueLower == 'error':
            level = logging.ERROR
        elif valueLower == 'warning':
            level = logging.WARNING
        elif valueLower == 'info':
            level = logging.INFO
        elif valueLower == 'debug':
            level = logging.DEBUG
        else:
            level = logging.ERROR

        setattr(namespace, self.dest, level)

# must communicate with SUMS database
def getFailedSUs(suList, conn):
    failedSUs = []

    try:
        with conn.cursor() as cursor:
            cmd = 'SELECT ds_index FROM sum_partn_alloc WHERE ds_index IN (' + ','.join([ str(sunum) for sunum in suList ]) + ')'
            sus = set()

            try:
                cursor.execute(cmd)
                rows = cursor.fetchall()
        
                for row in rows:
                    sus.add(row[0])
            except psycopg2.Error as exc:
                # handle database-command errors.
                import traceback
                raise DBCommandException(traceback.format_exc(5))

        # end SUMS DB transaction
    except psycopg2.Error as exc:
        import traceback
        raise DBCommandException(traceback.format_exc(5))
        
    for su in suList:
        if su not in sus:
            failedSUs.append(su)

    return failedSUs

if __name__ == "__main__":
    rv = RV_SUCCESS
    log = None

    try:
        rsumsDrmsParams = RsumsDrmsParams()
            
        parser = CmdlParser(usage='%(prog)s [ -dht ] [ --dbhost=<db host> ] [ --dbport=<db port> ] [ --dbname=<db name> ] [ --dbuser=<db user>] [ --logfile=<log-file name> ]')
        parser.add_argument('-H', '--dbhost', help='The host machine of the database that contains the series table from which records are to be deleted.', metavar='<db host machine>', dest='dbhost', default=rsumsDrmsParams.get('RS_DBHOST'))
        parser.add_argument('-P', '--dbport', help='The port on the host machine that is accepting connections for the database that contains the series table from which records are to be deleted.', metavar='<db host port>', dest='dbport', type=int, default=rsumsDrmsParams.get('RS_DBPORT'))
        parser.add_argument('-N', '--dbname', help='The name of the database that contains the series table from which records are to be deleted.', metavar='<db name>', dest='dbdatabase', default=rsumsDrmsParams.get('RS_DBNAME'))
        parser.add_argument('-U', '--dbuser', help='The name of the database user account.', metavar='<db user>', dest='dbuser', default=pwd.getpwuid(os.getuid())[0])
        parser.add_argument('-l', '--loglevel', help='Specifies the amount of logging to perform. In order of increasing verbosity: critical, error, warning, info, debug', dest='loglevel', action=LogLevelAction, default=logging.ERROR)
        parser.add_argument('-L', '--logfile', help='The file to which logging is written.', metavar='<log file>', dest='logfile', default=os.path.join(rsumsDrmsParams.get('RS_LOGDIR'), 'rsums-client-' + datetime.now().strftime('%Y%m%d') + '.log'))
        parser.add_argument('-c', '--capturetable', help='The database table in which are stored captured SUNUMs.', metavar='<capture table>', dest='ctable', default='drms.ingested_sunums')
        parser.add_argument('-r', '--requesttable', help='The database table in which remote SUMS requests are stored.', metavar='<requests table>', dest='rtable', default=rsumsDrmsParams.get('RS_REQUEST_TABLE'))
        parser.add_argument('-s', '--setup', help='Create an initialization SQL script to be run by the remote-sums-client database user.', dest='setup', action='store_true', default=False)
        
        arguments = Arguments(parser)
        
        # add all drmsParams to arguments
        arguments.setArg('RS_MAXTHREADS', int(rsumsDrmsParams.get('RS_MAXTHREADS')))
        arguments.setArg('DRMS_LOCK_DIR', rsumsDrmsParams.get('DRMS_LOCK_DIR'))
        arguments.setArg('SUMS_READONLY_DB_USER', rsumsDrmsParams.get('SUMS_READONLY_DB_USER'))
        arguments.setArg('SUMS_DB_HOST', rsumsDrmsParams.get('SUMS_DB_HOST'))
        arguments.setArg('SUMPGPORT', int(rsumsDrmsParams.get('SUMPGPORT')))
        arguments.setArg('RS_REQUEST_TABLE', rsumsDrmsParams.get('RS_REQUEST_TABLE'))
        
        pid = os.getpid()

        # Create/Initialize the log file.
        try:
            logFile = arguments.logfile
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')        
            log = Log(logFile, arguments.loglevel, formatter)
        except exc:
            raise LogException('unable to initialize logging')

        log.writeCritical([ 'starting rsums-clientd.py server.' ])
        arguments.dump(log)
        
        thContainer = [ arguments, str(pid), log, rv ]

        with TerminationHandler(thContainer) as th:                
            if arguments.setup:
                print('-- run this script as the a DB superuser')
                print('GRANT ALL ON drms.ingested_sunums TO ' + arguments.dbuser)
                raise TerminationHandler.Break

            # we are connected to both the DRMS and SUMS databases
            connSums = th.rsConnSums()
            
            pendingSUs = set()
            pendingRequests = {}

            # main loop
            loopIteration = 1
            while True:
                # re-connect to the db after some number of iterations
                if loopIteration % 100 == 0:
                    th.closeRsConnSums(True)
                    th.closeRsConn(True)
                    th.openRsConn()
                    th.openRsConnSums()

                with th.rsConn():
                    # start a transaction (transaction is committed when with block is left)
                    try:
                        with th.rsConn().cursor() as cursor:
                            tableIn = 'drms.ingested_sunums'
                            tableOut = arguments.RS_REQUEST_TABLE
                            
                            # we want to keep RS_MAXTHREADS SUs pending; operate on a small chunk of SUs at one time
                            while len(pendingSUs) < arguments.RS_MAXTHREADS:
                                # read 4 rows from the sunum-capture table
                                if len(pendingSUs) > 0:
                                    whereClause = ' WHERE sunum NOT IN (' + ','.join([ str(sunum) for sunum in list(pendingSUs) ]) + ')'
                                else:
                                    whereClause = ''
                                
                                cmd = 'SELECT sunum FROM ' + tableIn + whereClause + ' LIMIT 4'
                                try:
                                    cursor.execute(cmd)
                                    rows = cursor.fetchall()
                                    if len(rows) > 4:
                                        raise DBCommandResultException(exc.diag.message_primary)

                                    sunums = [ row[0] for row in rows ]
                                    sunumsStr = ','.join([ str(sunum) for sunum in sunums ])
                                except psycopg2.Error as exc:
                                    # handle database-command errors.
                                    import traceback
                                    raise DBCommandException(traceback.format_exc(5))

                                if len(sunums) <= 0:
                                    # no more SUs for which to request downloads; break
                                    break
                                else:
                                    log.writeInfo([ 'RS server has open slots and there are SUs to download - making new SU-download requests' ])
                                    # making a new request - generate next request ID
                                    cmd = "SELECT nextval('" + tableOut + "_seq')"

                                    try:
                                        cursor.execute(cmd)
                                        rows = cursor.fetchall()
                                        if len(rows) != 1:
                                            raise DBCommandResultException(exc.diag.message_primary)

                                        requestID = rows[0][0]
                                    except psycopg2.Error as exc:
                                        # handle database-command errors.
                                        import traceback
                                        raise DBCommandException(traceback.format_exc(5))
                                
                                    # make the Remote SUMS request (by inserting a row into the RS requests table)
                                    cmd = 'INSERT INTO ' + tableOut + '(requestid, dbhost, dbport, dbname, starttime, sunums, status) VALUES(' + str(requestID) + ", '" + arguments.dbhost + "', " + str(arguments.dbport) + ", '" + arguments.dbdatabase + "', " + 'clock_timestamp()' + ", '" + sunumsStr + "', " + "'N'" + ')'
                                    try:
                                        cursor.execute(cmd)
                                    except psycopg2.Error as exc:
                                        # handle database-command errors.
                                        import traceback
                                        raise DBCommandException(traceback.format_exc(5))
                                    
                                    log.writeInfo([ 'requested download of ' + sunumsStr + ' (id ' + str(requestID) + ')' ])
                                    
                                    # no errors, so we can update pendingSUs list
                                    for sunum in sunums:
                                        pendingSUs.add(sunum)
                                        log.writeDebug([ 'adding su ' + str(sunum) + ' to pendingSUs list' ])

                                    pendingRequests[str(requestID)] = sunums # map to a list
                                    log.writeDebug([ 'adding request ' + str(requestID) + ' to pendingRequests list' ])
                            
                            # give Remote SUMS a chance to process existing requests
                            time.sleep(1)
                                
                            # we've got our pendingSUs all started; now monitor them for completion
                            if len(pendingRequests) > 0:
                                toDelFromTableOut = []
                                toDelFromTableIn = []
                                toDelFromPendingRequests = []
                                toDelFromPendingSUs = []
                                
                                log.writeInfo([ 'checking on pending requests' ])

                                pendingRequestsStr = ','.join(pendingRequests.keys())
                                cmd = 'SELECT requestid, starttime, status, errmsg FROM ' + tableOut + ' WHERE requestid IN (' + pendingRequestsStr + ')'
                                
                                try:
                                    cursor.execute(cmd)
                                    rows = cursor.fetchall()
                                    
                                    # for a variety of reasons, items in pendingRequests could now be absent from the db response; 
                                    # remove those requests from pendingRequests and log an error
                                    reqsAlive = set()
                                    
                                    for row in rows:
                                        # these are rows from the RS requests table
                                        requestID = row[0] # int
                                        starttime = row[1] # datetime.datetime
                                        status = row[2] # string
                                        errmsg = row[3] # string
                                        
                                        reqsAlive.add(requestID)
                                        log.writeDebug([ 'request ' + str(requestID) + ' is alive and pending' ])
                                        
                                        if status == 'E':
                                            # log error
                                            log.writeError([ 'error processing requestID ' +  str(requestID) ])
                                            
                                            # find out which SUs, specifically, failed
                                            failedSUs = getFailedSUs(pendingRequests[str(requestID)], th.rsConnSums())
                                            for su in failedSUs:                                                
                                                log.writeError([ 'error downloading SU ' +  str(su) ])
                                            
                                            toDelFromTableOut.append(requestID)
                                            toDelFromPendingRequests.append(requestID)
                                            toDelFromTableIn.extend(pendingRequests[str(requestID)])
                                            # each request contains a unique set of SUNUMs (no SUNUM appears in more than one request)
                                            # so it is OK to remove the SUs in pendingRequests[str(requestID)] - we won't be removing 
                                            # them from other unrelated requests
                                            toDelFromPendingSUs.extend(pendingRequests[str(requestID)])
                                        elif status == 'C':
                                            log.writeInfo([ 'RS server has completed processing request ' + str(requestID) ])
                                            toDelFromTableOut.append(requestID)
                                            toDelFromPendingRequests.append(requestID)
                                            toDelFromTableIn.extend(pendingRequests[str(requestID)])
                                            # each request contains a unique set of SUNUMs (no SUNUM appears in more than one request)
                                            # so it is OK to remove the SUs in pendingRequests[str(requestID)] - we won't be removing 
                                            # them from other unrelated requests
                                            toDelFromPendingSUs.extend(pendingRequests[str(requestID)])
                                        elif datetime.now(starttime.tzinfo)  > starttime + timedelta(minutes=5):
                                            # time-out; let the server continue to attempt to download the SU, but 
                                            # the client gives up waiting and pretends that there was basically an error
                                            log.writeError([ 'time-out processing requestID ' +  str(requestID) ])

                                            for su in pendingRequests[str(requestID)]:                                                
                                                log.writeError([ 'time-out downloading SU ' +  str(su) ])
                                            
                                            # do not delete the request from the requests table; do not delete the SU from
                                            # the capture table again - this way the client will attempt to download the 
                                            # SU again later (at which point, it may already be downloaded)
                                            toDelFromPendingRequests.append(requestID)
                                            # each request contains a unique set of SUNUMs (no SUNUM appears in more than one request)
                                            # so it is OK to remove the SUs in pendingRequests[str(requestID)] - we won't be removing 
                                            # them from other unrelated requests
                                            toDelFromPendingSUs.extend(pendingRequests[str(requestID)])
                                    
                                    # handle lost requests - do not delete from capture table so the client will try again
                                    # later
                                    for requestID in [ int(key) for key in pendingRequests.keys() ]:
                                        if requestID not in reqsAlive:
                                            log.writeError([ 'pending request ' + str(requestID) + ' lost' ])
                                            
                                            toDelFromPendingRequests.append(requestID)
                                            # each request contains a unique set of SUNUMs (no SUNUM appears in more than one request)
                                            # so it is OK to remove the SUs in pendingRequests[str(requestID)] - we won't be removing 
                                            # them from other unrelated requests
                                            toDelFromPendingSUs.extend(pendingRequests[str(requestID)])
                                except psycopg2.Error as exc:
                                    # handle database-command errors.
                                    import traceback
                                    raise DBCommandException(traceback.format_exc(5))
                                    
                                # remove from drms.rs_requests
                                if len(toDelFromTableOut) > 0:
                                    requestIDStr = ','.join([ str(requestID) for requestID in toDelFromTableOut ])
                                    cmd = 'DELETE FROM ' + tableOut + ' WHERE requestid in (' + requestIDStr + ')'
                                
                                    try:
                                        cursor.execute(cmd)
                                    except psycopg2.Error as exc:
                                        # handle database-command errors.
                                        import traceback
                                        raise DBCommandException(traceback.format_exc(5))
                                    
                                    log.writeInfo([ 'removed requests ' + requestIDStr + ' from RS requests table' ])
                                
                                # remove from pendingRequests
                                if len(toDelFromPendingRequests):
                                    for requestID in toDelFromPendingRequests:
                                        del pendingRequests[str(requestID)]
                                    
                                    log.writeDebug([ 'removed ' + ','.join([ str(requestID) for requestID in toDelFromPendingRequests ]) + ' from pending requests list' ])

                                # remove from drms.ingested_sunums
                                if len(toDelFromTableIn) > 0:
                                    sunumStr = ','.join([ str(sunum) for sunum in toDelFromTableIn ])
                                    cmd = 'DELETE FROM ' + tableIn + ' WHERE sunum IN ' + '(' + sunumStr + ')'
                                
                                    try:
                                        cursor.execute(cmd)
                                    except psycopg2.Error as exc:
                                        # handle database-command errors.
                                        import traceback
                                        raise DBCommandException(traceback.format_exc(5))
                                
                                    log.writeInfo([ 'removed SUs ' + sunumStr + ' from sunum capture table' ])
                                
                                # remove from pendingSUs
                                if len(toDelFromPendingSUs) > 0:
                                    for sunum in toDelFromPendingSUs:
                                        pendingSUs.remove(sunum)
                                    
                                    log.writeDebug([ 'removed ' + ','.join([ str(sunum) for sunum in toDelFromPendingSUs ]) + ' from pending SUs list' ])
                    except psycopg2.Error as exc:
                        import traceback
                        raise DBCommandException(traceback.format_exc(5))
                        
                # end of DRMS DB transaction
                loopIteration += 1
            # leaving termination-handler block
        rv = thContainer[3]
    except RSException as exc:
        if log:
            log.writeError([ exc.args[0] ])
            
        rv = exc.rv

    if log:
        log.close()
    logging.shutdown()

    sys.exit(rv)