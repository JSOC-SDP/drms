#!/usr/bin/env python3
import sys
import re
import os
import shutil
import psutil
import threading
import socket
import signal
import select
import copy
from datetime import datetime, timedelta, timezone
import time
import re
import random
import json
import uuid
import logging
import argparse
import inspect
from functools import partial
from subprocess import check_call, CalledProcessError
from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value
from ctypes import c_longlong
from pathlib import Path
import psycopg2
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../include'))
from drmsparams import DRMSParams
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../base/libs/py'))
from drmsCmdl import CmdlParser
from drmsLock import DrmsLock

if sys.version_info < (3, 2):
    raise Exception('you must run the 3.2 release, or a more recent release, of Python')


SUMSD = 'sumsd'
LISTEN_PORT = '<listen port>'
SUM_MAIN = 'public.sum_main'
SUM_PARTN_ALLOC = 'public.sum_partn_alloc'
SUM_ARCH_GROUP = 'public.sum_arch_group'
SUM_PARTN_AVAIL = 'public.sum_partn_avail'

DARW = 1
DADP = 2
DAAP = 4
DAAEDDP = 32
DAAPERM = 64
DAADP = 128

# Return code
RV_SUCCESS = 0
RV_DRMSPARAMS = 1
RV_ARGS = 2
RV_LOG = 3
RV_POLL = 4
RV_SOCKET = 5
RV_DBCONNECTION = 6
RV_DBCOMMAND = 7
RV_TERMINATED = 8
RV_RECEIVEMSG = 9
RV_SENDMSG = 10
RV_JSONIZE = 11
RV_UNJSONIZE = 12
RV_CLIENTINFO = 13
RV_EXTRACTREQUEST = 14
RV_REQUESTTYPE = 15
RV_SESSIONOPENED = 16
RV_SESSIONCLOSED = 17
RV_SESSIONROLLEDBACK = 18
RV_GENERATERESPONSE = 19
RV_IMPLEMENTATION = 20
RV_TAPEREQUEST = 21
RV_SUMSCHMOWN = 22
RV_PUTFILE = 23
RV_SU_FILE_OWNER_MOD_UPDATER = 24
RV_UNKNOWNERROR = 25


# Request types
REQUEST_TYPE_OPEN = 'open'
REQUEST_TYPE_CLOSE = 'close'
REQUEST_TYPE_ROLLBACK = 'rollback'
REQUEST_TYPE_INFO = 'info'
REQUEST_TYPE_GET = 'get'
REQUEST_TYPE_ALLOC= 'alloc'
REQUEST_TYPE_PUT = 'put'
REQUEST_TYPE_DELETESERIES = 'deleteseries'
REQUEST_TYPE_PING = 'ping'
REQUEST_TYPE_POLL = 'poll'
REQUEST_TYPE_INFOARRAY = 'infoarray'

# Exception status codes
RESPSTATUS_OK = 'ok'
RESPSTATUS_BROKENCONNECTION = 'broken-connection'
RESPSTATUS_JSON = 'bad-json'
RESPSTATUS_MSGRECEIVE = 'cant-receive-request'
RESPSTATUS_MSGSEND = 'cant-send-response'
RESPSTATUS_CLIENTINFO = 'bad-clientinfo'
RESPSTATUS_REQ = 'bad-request'
RESPSTATUS_REQTYPE = 'bad-request-type'
RESPSTATUS_SESSIONCLOSED = 'session-closed'
RESPSTATUS_SESSIONOPENED = 'session-opened'
RESPSTATUS_SESSIONROLLEDBACK = 'session-rolledback'
RESPSTATUS_GENRESPONSE = 'cant-generate-response'
RESPSTATUS_TAPEREAD = 'taperead'
RESPSTATUS_SERVICEREQUEST = 'cant-service-request' # an 'other' type of error (like OSError)

# JSON keys
IS_ALIVE = 'is-alive'

# Maximum number of DB rows returned
MAX_MTSUMS_NSUS = 32768

SUMS_CHMOWN_LOCK_FILE = '.sum_chmown_lock'

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

        if thContainer[2] is None:
            raise ArgsException('TermationHandler constructor: log cannot be None')
        arguments = thContainer[0]
        self.pidStr = thContainer[1]
        self.log = thContainer[2]

        super(TerminationHandler, self).__init__()

    def __enter__(self):
        signal.signal(signal.SIGINT, terminator)
        signal.signal(signal.SIGTERM, terminator)
        signal.signal(signal.SIGHUP, terminator)

        # open DB connections
        try:
            maxconn = int(arguments.getArg('maxconn'))
        except ArgsException as exc:
            maxconn = DBConnection.maxConn

        for nConn in range(0, maxconn):
            DBConnection.connList.append(DBConnection(arguments.getArg('dbhost'), arguments.getArg('dbport'), arguments.getArg('database'), arguments.getArg('dbuser'), log))

    # Normally, __exit__ is called if an exception occurs inside the with block. And since SIGINT is converted
    # into a KeyboardInterrupt exception, it will be handled by __exit__(). However, SIGTERM will not -
    # __exit__() will be bypassed if a SIGTERM signal is received. Use the signal handler installed in the
    # __enter__() call to handle SIGTERM.
    def __exit__(self, etype, value, traceback):
        self.log.write_info([ 'TerminationHandler.__exit__() called' ])

        # clean up DB connections
        DBConnection.closeAll()
        self.log.write_info([ 'termination handler closed all DB connections' ])

        # wait for Worker threads to exit
        while True:
            Worker.lockTList()
            worker = None

            try:
                if len(Worker.tList) > 0:
                    worker = Worker.tList[0]
                else:
                    break
            except:
                break
            finally:
                Worker.unlockTList()

            if worker and isinstance(worker, (Worker)) and worker.is_alive():
                # can't hold worker lock here - when the worker terminates, it acquires the same lock;
                # due to a race condition in tList (we had to release the tList lock), we have to check
                # to see if the worker is alive before joining it.
                self.log.write_info([ 'termination handler waiting for worker ' +  worker.getID() + ' to terminate' ])
                worker.join() # will block, possibly for ever

        if etype == self.Break:
            # suppress exception propagation outside of the context (normally the exception that causes execution to exit
            # this context-manager block gets re-raised outside of this block upon exit).
            return True

        if etype == SystemExit:
            raise TerminationException('termination signal handler called')


class SumsDrmsParams(DRMSParams):

    def __init__(self):
        super(SumsDrmsParams, self).__init__()

    def get(self, name):
        val = super(SumsDrmsParams, self).get(name)

        if val is None:
            raise ParamsException('unknown DRMS parameter: ' + name)
        return val

    def get_optional(self, name):
        # if the parameter does not exist, returns None
        return super(SumsDrmsParams, self).get(name)

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
                type, msg = exc.args

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

    def replArg(self, name, newValue):
        if hasattr(self, name):
            setattr(self, name, newValue)
        else:
            raise ArgsException('attempt to replace an argument value for an argument that does not already exist: ' + name)

    def setAllArgs(self):
        for key,val in list(vars(self.parsedArgs).items()):
            self.setArg(key, val)

    def getArg(self, name):
        try:
            return getattr(self, name)
        except AttributeError as exc:
            raise ArgsException('unknown argument: ' + name)


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

    def __prependFrameInfo(self, msg):
        frame, fileName, lineNo, fxn, context, index = inspect.stack()[2]
        return os.path.basename(fileName) + ':' + str(lineNo) + ': ' + msg

    def write_debug(self, text):
        if self.log:
            for line in text:
                self.log.debug(self.__prependFrameInfo(line))
            self.fileHandler.flush()

    def write_info(self, text):
        if self.log:
            for line in text:
                self.log.info(self.__prependFrameInfo(line))
        self.fileHandler.flush()

    def write_warning(self, text):
        if self.log:
            for line in text:
                self.log.warning(self.__prependFrameInfo(line))
            self.fileHandler.flush()

    def write_error(self, text):
        if self.log:
            for line in text:
                self.log.error(self.__prependFrameInfo(line))
            self.fileHandler.flush()

    def write_critical(self, text):
        if self.log:
            for line in text:
                self.log.critical(self.__prependFrameInfo(line))
            self.fileHandler.flush()

class SDException(Exception):

    def __init__(self, msg):
        frame, file_name, line_number, method, context, index = inspect.stack()[2]
        decorated_msg = '[ exception at line {line_number} ] {msg}'.format(line_number=line_number, msg=msg.rstrip('\n'))
        super(SDException, self).__init__(decorated_msg)

class ParamsException(SDException):

    retcode = RV_DRMSPARAMS
    def __init__(self, msg):
        super(ParamsException, self).__init__(msg)

class ArgsException(SDException):

    retcode = RV_ARGS
    def __init__(self, msg):
        super(ArgsException, self).__init__(msg)

class LogException(SDException):

    retcode = RV_LOG
    def __init__(self, msg):
        super(LogException, self).__init__(msg)

class PollException(SDException):

    retcode = RV_POLL
    def __init__(self, msg):
        super(PollException, self).__init__(msg)

class SocketConnectionException(SDException):

    retcode = RV_SOCKET
    def __init__(self, msg):
        super(SocketConnectionException, self).__init__(msg)

class DBConnectionException(SDException):

    retcode = RV_DBCONNECTION
    def __init__(self, msg):
        super(DBConnectionException, self).__init__(msg)

class DBCommandException(SDException):

    retcode = RV_DBCOMMAND
    def __init__(self, msg):
        super(DBCommandException, self).__init__(msg)

class TerminationException(SDException):

    retcode = RV_TERMINATED
    def __init__(self, msg):
        super(TerminationException, self).__init__(msg)

class ReceiveMsgException(SDException):

    retcode = RV_RECEIVEMSG
    def __init__(self, msg):
        super(ReceiveMsgException, self).__init__(msg)

class SendMsgException(SDException):

    retcode = RV_SENDMSG
    def __init__(self, msg):
        super(SendMsgException, self).__init__(msg)

class JsonizerException(SDException):

    retcode = RV_JSONIZE
    def __init__(self, msg):
        super(JsonizerException, self).__init__(msg)

class UnjsonizerException(SDException):

    retcode = RV_UNJSONIZE
    def __init__(self, msg):
        super(UnjsonizerException, self).__init__(msg)

class ClientInfoException(SDException):

    retcode = RV_CLIENTINFO
    def __init__(self, msg):
        super(ClientInfoException, self).__init__(msg)

class ExtractRequestException(SDException):

    retcode = RV_EXTRACTREQUEST
    def __init__(self, msg):
        super(ExtractRequestException, self).__init__(msg)

class RequestTypeException(SDException):

    retcode = RV_REQUESTTYPE
    def __init__(self, msg):
        super(RequestTypeException, self).__init__(msg)

class SessionOpenedException(SDException):

    retcode = RV_SESSIONOPENED
    def __init__(self, msg):
        super(SessionOpenedException, self).__init__(msg)

class SessionClosedException(SDException):

    retcode = RV_SESSIONCLOSED
    def __init__(self, msg):
        super(SessionClosedException, self).__init__(msg)

class SessionRolledbackException(SDException):

    retcode = RV_SESSIONROLLEDBACK
    def __init__(self, msg):
        super(SessionRolledbackException, self).__init__(msg)

class GenerateResponseException(SDException):

    retcode = RV_GENERATERESPONSE
    def __init__(self, msg):
        super(GenerateResponseException, self).__init__(msg)

class ImplementationException(SDException):

    retcode = RV_IMPLEMENTATION
    def __init__(self, msg):
        super(ImplementationException, self).__init__(msg)


class TaperequestException(SDException):

    retcode = RV_TAPEREQUEST
    def __init__(self, msg):
        super(TaperequestException, self).__init__(msg)

class SumsChmownException(SDException):

    retcode = RV_SUMSCHMOWN
    def __init__(self, msg):
        super(SumsChmownException, self).__init__(msg)

class PutFileException(SDException):

    retcode = RV_PUTFILE
    def __init__(self, msg):
        super(PutFileException, self).__init__(msg)

class SUFileOwnerModUpdaterException(SDException):

    retcode = RV_SU_FILE_OWNER_MOD_UPDATER
    def __init__(self, msg):
        super(SUFileOwnerModUpdaterException, self).__init__(msg)


class DBConnection(object):
    connList = [] # list of existing DB connections
    connListFree = [] # list of currently unused DB connections
    connListLock = threading.RLock() # guard list access - the thread that has the lock can call acquire(), and it will not block
    maxConn = 16 # default
    eventConnFree = threading.Event() # event fired when a connection gets freed up
    nextIDseq = 0 # the id of the next connection

    def __init__(self, host, port, database, user, log):
        self.conn = None

        if host is None or port is None or database is None or user is None or log is None:
            raise ArgsException('DBConnection constructor: neither host nor port nor database nor user nor log can be None')

        self.id = str(DBConnection.nextIDseq) # do not call the constructor from more than one thread!
        DBConnection.nextIDseq += 1

        # Connect to the db. If things succeed, then save the db-connection information.
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.log = log
        self.openConnection()

    def getID(self):
        return self.id

    def commit(self):
        # Does not close DB connection. It can be used after the commit() call.
        if not self.conn:
            raise DBCommandException('cannot commit - no database connection exists')

        if self.conn:
            self.conn.commit()

    def rollback(self):
        # Does not close DB connection. It can be used after the rollback() call.
        if not self.conn:
            raise DBCommandException('cannot rollback - no database connection exists')

        if self.conn:
            self.conn.rollback()

    def close(self):
        # Does a rollback, then closes DB connection so that it can no longer be used.
        self.closeConnection()

    def openConnection(self):
        if self.conn:
            raise DBConnectionException('already connected to the database')

        try:
            self.conn = psycopg2.connect(host=self.host, port=self.port, database=self.database, user=self.user)
            self.log.write_info([ 'user ' + self.user + ' successfully connected to ' + self.database + ' database: ' + self.host + ':' + str(self.port) + ' - id ' + self.id ])
        except psycopg2.OperationalError as exc:
            # Closes the cursor and connection
            raise DBConnectionException(str(exc))

        # must add to the list of connections and free connections
        DBConnection.connListLock.acquire()
        try:
            DBConnection.connList.append(self)
            DBConnection.connListFree.append(self)
        finally:
            DBConnection.connListLock.release()

        self.log.write_debug([ 'added connection ' + self.id + ' to connection list and free connection list' ])

    def closeConnection(self):
        if not self.conn:
            raise DBConnectionException('there is no database connection')

        if self.conn:
            DBConnection.connListLock.acquire()
            try:
                self.conn.close()
                self.log.write_info([ 'closed DB connection ' + self.id ])

                if self in DBConnection.connListFree:
                    DBConnection.connListFree.remove(self)
                    self.log.write_debug([ 'removed DB connection ' + self.id + ' from free connection list'])
                DBConnection.connList.remove(self)
                self.log.write_debug([ 'removed DB connection ' + self.id + ' from connection list'])

            finally:
                DBConnection.connListLock.release()

    def release(self):
        DBConnection.connListLock.acquire()
        try:
            # add this connection to the free list
            DBConnection.connListFree.append(self)

            # signal a thread waiting for an open connection (if there were previously no slots open)
            if len(DBConnection.connListFree) == 1:
                # fire event so that worker can obtain a DB slot
                DBConnection.eventConnFree.set()
                # clear event so that a worker will block the next time it calls wait()
                DBConnection.eventConnFree.clear()
        finally:
            DBConnection.connListLock.release()

    def exeCmd(self, cmd, results, result=True):
        if not self.conn:
            raise DBCommandException('cannot execute database command ' + cmd + ' - no database connection exists')

        if result:
            try:
                with self.conn.cursor('namedCursor') as cursor:
                    cursor.itersize = 4096

                    try:
                        cursor.execute(cmd)
                        for row in cursor:
                            results.append(row) # results is a list of lists
                    except psycopg2.Error as exc:
                        # Handle database-command errors.
                        raise DBCommandException(exc.diag.message_primary)
            except psycopg2.Error as exc:
                raise DBCommandException(exc.diag.message_primary)
        else:
            try:
                with self.conn.cursor() as cursor:
                    try:
                        cursor.execute(cmd)
                    except psycopg2.Error as exc:
                        # Handle database-command errors.
                        raise DBCommandException(exc.diag.message_primary)
            except psycopg2.Error as exc:
                raise DBCommandException(exc.diag.message_primary)

    @classmethod
    def nextOpenConnection(cls):
        conn = None
        while True:
            cls.connListLock.acquire()
            try:
                if len(cls.connListFree) > 0:
                    conn = cls.connListFree.pop(0)
                    break # the finally clause will ensure the connList lock is released
            finally:
                cls.connListLock.release()

            # There were no free threads. Wait until there is a free thread.
            cls.eventConnFree.wait()
            # We woke up, because a free DB connection became available. However, that DB connection could
            # now be in use. Loop and check again.

        return conn

    @classmethod
    def closeAll(cls):
        cls.connListLock.acquire()
        try:
            for conn in cls.connList:
                conn.closeConnection()
        finally:
            cls.connListLock.release()

class DataObj(object):
    pass


class Jsonizer(object):
    def __init__(self, dataObj):
        self.data = dataObj
        try:
            self.json = json.dumps(dataObj)
        except ValueError as exc:
            raise JsonizerException(str(exc))
        except TypeError as exc:
            raise JsonizerException(str(exc))

    def getJSON(self):
        return self.json


class Unjsonizer(object):
    def __init__(self, jsonStr):
        self.json = jsonStr
        try:
            self.unjsonized = json.loads(jsonStr) # JSON objects are converted to Python dictionaries!
        except ValueError as exc:
            raise UnjsonizerException(str(exc))
        except TypeError as exc:
            raise UnjsonizerException(str(exc))


class Request(object):
    _numInfoSUS = 3 # the number of SUs to print when showing request information (not representation)

    def __init__(self, reqType, unjsonized, worker):
        self.reqType = reqType
        self.unjsonized = unjsonized.unjsonized # a request-specific dictionary
        self.worker = worker
        self.data = DataObj()
        if 'sessionid' in self.unjsonized:
            # Only the OpenRequest will not have a sessionid.
            self.data.sessionid = Request.hexToInt(self.unjsonized['sessionid'])

    def _reprify(self):
        # by default, use object formal representation
        self._stringrepr('reprDict')

    def _stringify(self):
        # by default, use object formal representation
        self._stringrepr('strDict')

    def __repr__(self):
        self._reprify()
        return str(self.reprDict)

    def __str__(self):
        self._stringify()
        return str(self.strDict)

    def _stringifyType(self, whichDict):
        if not hasattr(self, whichDict):
            setattr(self, whichDict, { 'reqtype' : self.reqType })

    def getType(self):
        return self.reqType

    def generateResponse(self, dest=None):
        pass

    def generateErrorResponse(self, status, errMsg):
        return ErrorResponse(self, status, errMsg)

    def generateAliveResponse(self):
        return AliveResponse(self)

    @staticmethod
    def hexToInt(hexStr):
        return int(hexStr, 16)


class OpenRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'open'
    }
    """
    def __init__(self, unjsonized, worker):
        super(OpenRequest, self).__init__(REQUEST_TYPE_OPEN, unjsonized, worker)
        # No data for this request.

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)

    def generateResponse(self, dest=None):
        resp = OpenResponse(self, RESPSTATUS_OK, dest)
        super(OpenRequest, self).generateResponse(dest)
        return resp


class CloseRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'close',
        'sessionid' : '1AE2FC'
    }
    """
    def __init__(self, unjsonized, worker):
        super(CloseRequest, self).__init__('close', unjsonized, worker)

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid

    def generateResponse(self, dest=None):
        resp = CloseResponse(self, RESPSTATUS_OK, dest)
        super(CloseRequest, self).generateResponse(dest)
        return resp


class RollbackRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'rollback',
        'sessionid' : '1AE2FC'
    }
    """
    def __init__(self, unjsonized, worker):
        super(RollbackRequest, self).__init__('rollback', unjsonized, worker)

    def _stringrepr(self, whichDict):
          self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid

    def generateResponse(self, dest=None):
        resp = RollbackResponse(self, RESPSTATUS_OK, dest)
        super(RollbackRequest, self).generateResponse(dest)
        return resp


class InfoRequest(Request):
    """
    unjsonized is:
    {
       'reqtype' : 'info',
       'sessionid' : '1AE2FC',
       'sus' : [ '3039', '5BA0' ]
    }
    """
    def __init__(self, unjsonized, worker):
        super(InfoRequest, self).__init__('info', unjsonized, worker)

        if len(self.unjsonized['sus']) > MAX_MTSUMS_NSUS:
            raise ExtractRequestException('too many SUs in request (maximum of ' + str(MAX_MTSUMS_NSUS) + ' allowed)')

        self.data.sus = [ Request.hexToInt(hexStr) for hexStr in self.unjsonized['sus'] ]

        processed = set()
        self.data.sulist = []

        # sus may contain duplicates. They must be removed.
        for su in self.data.sus:
            if str(su) not in processed:
                self.data.sulist.append(str(su)) # Make a list of strings - we'll need to concatenate the elements into a comma-separated list for the DB query.
                processed.add(str(su))

    def _stringify(self):
        self.__stringinfo('strDict')

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['sus'] = self.data.sus

    def __stringinfo(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['sus'] = self.data.sus[0:Request._numInfoSUS]
            strDict['sus'].append('...')

    def generateResponse(self, dest=None):
        resp = InfoResponse(self, RESPSTATUS_OK, dest)
        super(InfoRequest, self).generateResponse(dest)
        return resp

class GetRequest(Request):
    """
    unjsonized is:
    {
       'reqtype' : 'get',
       'sessionid' : '1AE2FC',
       'touch' : True,
       'retrieve' : False,
       'retention' : 60,
       'sus' : ['1DE2D412', '1AA72414']
    }
    """
    def __init__(self, unjsonized, worker):
        super(GetRequest, self).__init__('get', unjsonized, worker)

        if len(self.unjsonized['sus']) > MAX_MTSUMS_NSUS:
            raise ExtractRequestException('too many SUs in request (maximum of ' + str(MAX_MTSUMS_NSUS) + ' allowed)')

        self.data.touch = self.unjsonized['touch']
        self.data.retrieve = self.unjsonized['retrieve']
        self.data.retention = self.unjsonized['retention']
        self.data.sus = [ Request.hexToInt(hexStr) for hexStr in self.unjsonized['sus'] ]

        processed = set()
        self.data.susNoDupes = []

        # sus may contain duplicates. They must be removed.
        for su in self.data.sus:
            if str(su) not in processed:
                self.data.susNoDupes.append(str(su)) # Make a list of strings - we'll need to concatenate the elements into a comma-separated list for the DB query.
                processed.add(str(su))

    def _stringify(self):
        self.__stringinfo('strDict')

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['touch'] = self.data.touch
            strDict['retrieve'] = self.data.retrieve
            strDict['retention'] = self.data.retention
            strDict['sus'] = self.data.sus

    def __stringinfo(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['touch'] = self.data.touch
            strDict['retrieve'] = self.data.retrieve
            strDict['retention'] = self.data.retention
            strDict['sus'] = self.data.sus[0:Request._numInfoSUS]
            strDict['sus'].append('...')

    def generateResponse(self, dest=None):
        resp = GetResponse(self, RESPSTATUS_OK, dest)
        super(GetRequest, self).generateResponse(dest)
        return resp


class AllocRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'alloc',
        'sessionid' : '1AE2FC',
        'sunum' : '82C5E02A',
        'sugroup' : 22,
        'numbytes' : 1024
    }

    or

    unjsonized is:
    {
        'reqtype' : 'alloc',
        'sessionid' : '1AE2FC',
        'sunum' : None,
        'sugroup' : 22,
        'numbytes' : 1024
    }
    """
    def __init__(self, unjsonized, worker):
        super(AllocRequest, self).__init__('alloc', unjsonized, worker)

        if self.unjsonized['sunum']:
            self.data.sunum = Request.hexToInt(self.unjsonized['sunum'])
        else:
            # Do not create the sunum attribute. A check later looks for sunum existence.
            pass
        self.data.sugroup = self.unjsonized['sugroup']
        self.data.numbytes = self.unjsonized['numbytes']

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        # there is only a single SU - not a list, so there is no need for __stringinfo() to be defined
        if not hasattr(self, whichDict):
            if hasattr(self.data, 'sunum'):
                sunumStr = str(self.data.sunum)
            else:
                sunumStr = None

            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['sunum'] = sunumStr
            strDict['sugroup'] = self.data.sugroup
            strDict['numbytes'] = self.data.numbytes

    def generateResponse(self, dest=None):
        resp = AllocResponse(self, RESPSTATUS_OK, dest)
        super(AllocRequest, self).generateResponse(dest)
        return resp


class PutRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'put',
        'sessionid' : '1AE2FC',
        'sudirs' : [ {'2B13493A' : '/SUM19/D722684218'}, {'2B15A227' : '/SUM12/D722838055'} ],
        'series' : 'hmi.M_720s',
        'retention' : 14,
        'archivetype' : 'temporary+archive'
    }
    """
    def __init__(self, unjsonized, worker):
        super(PutRequest, self).__init__('put', unjsonized, worker)

        if len(self.unjsonized['sudirs']) > MAX_MTSUMS_NSUS:
            raise ExtractRequestException('too many SUs in request (maximum of ' + str(MAX_MTSUMS_NSUS) + ' allowed)')

        sudirsNoDupes = []
        processed = set()

        # self.unjsonized['sudirs'] may contain duplicates. They must be removed. We do not need to keep track of the
        # original list with duplicates, however, since we won't be returning any information back to caller.
        for elem in sorted(self.unjsonized['sudirs'], key=self.suSort):
            [(hexStr, path)] = elem.items()
            suStr = str(Request.hexToInt(hexStr))
            if suStr not in processed:
                sudirsNoDupes.append({ suStr : path.rstrip('/')}) # make a list of strings - we'll need to concatenate the elements into a comma-separated list for the DB query; remove trailing slash, if one exists
                processed.add(suStr)

        self.data.sudirsNoDupes = sudirsNoDupes
        self.data.series = self.unjsonized['series']
        if 'retention' in self.unjsonized:
            self.data.retention = self.unjsonized['retention']
        else:
            # Don't know why the RPC SUMS has a default for this parameter, but not most others.
            self.data.retention = 2
        self.data.archivetype = self.unjsonized['archivetype']

    def _stringify(self):
        self.__stringinfo('strDict')

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['sudirs'] = self.unjsonized['sudirs']
            strDict['series'] = self.data.series
            strDict['retention'] = self.data.retention
            strDict['archivetype'] = self.data.archivetype

    def __stringinfo(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['sudirs'] = self.unjsonized['sudirs'][0:Request._numInfoSUS]
            strDict['sudirs'].append('...')
            strDict['series'] = self.data.series
            strDict['retention'] = self.data.retention
            strDict['archivetype'] = self.data.archivetype

    def generateResponse(self, dest=None):
        resp = PutResponse(self, RESPSTATUS_OK, dest)
        super(PutRequest, self).generateResponse(dest)
        return resp

    @classmethod
    def suSort(cls, elem):
        [(hexStr, path)] = elem.items()
        return Request.hexToInt(hexStr)


class DeleteseriesRequest(Request):
    """
    unjsonized is:
    {
    'reqtype' : 'deleteseries',
    'sessionid' : '1AE2FC',
    'series' : 'hmi.M_720s'
    }
    """
    def __init__(self, unjsonized, worker):
        super(DeleteseriesRequest, self).__init__('deleteseries', unjsonized, worker)

        self.data.series = self.unjsonized['series']

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['series'] = self.data.series

    def generateResponse(self, dest=None):
        resp = DeleteseriesResponse(self, RESPSTATUS_OK, dest)
        super(DeleteseriesRequest, self).generateResponse(dest)
        return resp


class PingRequest(Request):
    """
    unjsonized is:
    {
        'reqtype' : 'ping',
        'sessionid' : '1AE2FC'
    }
    """
    def __init__(self, unjsonized, worker):
        super(PingRequest, self).__init__('ping', unjsonized, worker)

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid

    def generateResponse(self, dest=None):
        resp = PingResponse(self, RESPSTATUS_OK, dest)
        super(PingRequest, self).generateResponse(dest)
        return resp


class PollRequest(Request):
    """
    {
        "reqtype" : "poll",
        "sessionid" : 7035235,
        "requestid" : "123e4567-e89b-12d3-a456-426655440000"
    }
    """
    def __init__(self, unjsonized, worker):
        super(PollRequest, self).__init__('poll', unjsonized, worker)

        self.data.requestid = self.unjsonized['requestid']

    def _stringrepr(self, whichDict):
        self.__stringrepr(whichDict)

    def __stringrepr(self, whichDict):
        if not hasattr(self, whichDict):
            self._stringifyType(whichDict)
            strDict = getattr(self, whichDict)
            strDict['sessionid'] = self.data.sessionid
            strDict['requestid'] = self.data.requestid

    def generateResponse(self, dest=None):
        resp = PollResponse(self, RESPSTATUS_OK, dest)
        super(PollRequest, self).generateResponse(dest)


class WriteRequest(Request):
    """
    {
        "reqtype" : "write",


    }
    """
class InfoRequestOLD(Request):
    """
    unjsonized is:
    {
       'reqtype' : 'infoArray',
       'sulist' : [ '3039', '5BA0' ]
    }
    """
    def __init__(self, unjsonized, worker):
        super(InfoRequestOLD, self).__init__('infoarray', unjsonized, worker)

        if len(self.unjsonized['sulist']) > MAX_MTSUMS_NSUS:
            raise ExtractRequestException('too many SUs in request (maximum of ' + str(MAX_MTSUMS_NSUS) + ' allowed)')

        self.data.sus = [ Request.hexToInt(hexStr) for hexStr in self.unjsonized['sulist'] ]

        processed = set()
        self.data.sulist = []

        # sus may contain duplicates. They must be removed.
        for su in self.data.sus:
            if str(su) not in processed:
                self.data.sulist.append(str(su)) # Make a list of strings - we'll need to concatenate the elements into a comma-separated list for the DB query.
                processed.add(str(su))

    def generateResponse(self, dest=None):
        resp = InfoResponseOLD(self, RESPSTATUS_OK, dest)
        super(InfoRequestOLD, self).generateResponse(dest)
        return resp

class RequestFactory(object):
    def __init__(self, worker):
        self.worker = worker

    def getRequest(self, jsonStr):
        unjsonized = Unjsonizer(jsonStr)

        if 'reqtype' not in unjsonized.unjsonized:
            raise ExtractRequestException('reqtype is missing from request')

        reqType = unjsonized.unjsonized['reqtype'].lower()
        if reqType == REQUEST_TYPE_OPEN:
            return OpenRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_CLOSE:
            return CloseRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_ROLLBACK:
            return RollbackRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_INFO:
            return InfoRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_GET:
            return GetRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_ALLOC:
            return AllocRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_PUT:
            return PutRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_DELETESERIES:
            return DeleteseriesRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_PING:
            return PingRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_POLL:
            return PollRequest(unjsonized, self.worker)
        elif reqType == REQUEST_TYPE_INFOARRAY:
            # Backward compatibility with first version of sumsd.py client.
            return InfoRequestOLD(unjsonized, self.worker)
        else:
            raise RequestTypeException('the request type ' + reqType + ' is not supported')


class Response(object):
    def __init__(self, request, status):
        self.request = request
        self.cmd = None
        self.dbRes = None
        self.data = {} # A Py dictionary containing the response to the request. Will be JSONized before being sent to client.
        self.data['status'] = status
        self.jsonizer = None

    def __str__(self):
        if not hasattr(self, 'rspDict'):
            self._createRspDict()
            self._stringify()
        return str(self.rspDict)

    def _createRspDict(self):
        if not hasattr(self, 'rspDict'):
            self.rspDict = { 'status' : self.data['status'] }

    def exeDbCmd(self):
        self.request.worker.log.write_debug([ 'db command is: ' + self.cmd ])
        self.request.worker.dbconn.exeCmd(self.cmd, self.dbRes, True)

    def exeDbCmdNoResult(self):
        self.request.worker.log.write_debug([ 'db command is: ' + self.cmd ])
        self.request.worker.dbconn.exeCmd(self.cmd, None, False)


    def getJSON(self, error=False, errMsg=None):
        self.jsonizer = Jsonizer(self.data)
        return self.jsonizer.getJSON()

    @staticmethod
    def stripHexPrefix(hexadecimal):
        regexp = re.compile(r'^\s*0x(\S+)', re.IGNORECASE)
        match = regexp.match(hexadecimal)
        if match:
            return match.group(1)
        else:
            return hexadecimal

    @staticmethod
    def intToHex(bigint):
        return Response.stripHexPrefix(hex(bigint))

class ErrorResponse(Response):
    def __init__(self, request, status, errMsg):
        super(ErrorResponse, self).__init__(request, status)
        msg = 'Unable to create ' + request.reqType + ' response: ' + errMsg

        request.worker.log.write_debug([ 'error: status (' + str(status) + '), msg (' + msg + ')' ])

        self.data['errmsg'] = msg

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(ErrorResponse, self)._createRspDict()

        if not 'errmsg' in self.rspDict:
            self.rspDict['errmsg'] = self.data['errmsg']


class AliveResponse(Response):
    def __init__(self, request):
        super(AliveResponse, self).__init__(request, RESPSTATUS_OK)
        self.data[IS_ALIVE] = True

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(AliveResponse, self)._createRspDict()

        if not IS_ALIVE in self.rspDict:
            self.rspDict[IS_ALIVE] = self.data[IS_ALIVE]


class OpenResponse(Response):
    def __init__(self, request, status, dest=None):
        super(OpenResponse, self).__init__(request, status)

        self.dbRes = []
        self.cmd = "SELECT nextval('public.sum_seq')"
        self.exeDbCmd()

        if len(self.dbRes) != 1 or len(self.dbRes[0]) != 1:
            raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

        sessionid = self.dbRes[0][0] # self.dbRes is a list of lists (or a 'table')

        self.cmd = 'INSERT INTO public.sum_open(sumid, open_date) VALUES (' + str(sessionid) + ', localtimestamp)'
        self.exeDbCmdNoResult()

        self.data['sessionid'] = Response.intToHex(sessionid)

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(OpenResponse, self)._createRspDict()

        if not 'sessionid' in self.rspDict:
            self.rspDict['sessionid'] = Request.hexToInt(self.data['sessionid'])

    def undo(self):
        # all DB changes will be rolled back on error, so nothing to do here
        pass


class CloseResponse(Response):
    def __init__(self, request, status, dest=None):
        super(CloseResponse, self).__init__(request, status)

        self.cmd = 'DELETE FROM public.sum_partn_alloc WHERE sumid = ' + str(self.request.data.sessionid) + ' AND (status = 8 OR status = 1)'
        self.exeDbCmdNoResult()

        self.cmd = 'DELETE FROM public.sum_open WHERE sumid = ' + str(self.request.data.sessionid)
        self.exeDbCmdNoResult()

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(CloseResponse, self)._createRspDict()

    def undo(self):
        # all DB changes will be rolled back on error, so nothing to do here
        pass


class RollbackResponse(Response):
    def __init__(self, request, status, dest=None):
        super(RollbackResponse, self).__init__(request, status)

        # nothing else to do

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(RollbackResponse, self)._createRspDict()

    def undo(self):
        # this should never be called
        pass


class InfoResponse(Response):
    def __init__(self, request, status, dest=None):
        super(InfoResponse, self).__init__(request, status)

        # Extract response data from the DB.
        dbInfo = [] # In theory there could be multiple DB requests.
        self.dbRes = []
        # Get DB info for unique SUs only (the sulist list does not contain duplicates).
        self.cmd = "SELECT T1.ds_index, T1.online_loc, T1.online_status, T1.archive_status, T1.offsite_ack, T1.history_comment, T1.owning_series, T1.storage_group, T1.bytes, T1.create_sumid, T1.creat_date, T1.username, COALESCE(T1.arch_tape, 'N/A'), COALESCE(T1.arch_tape_fn, 0), COALESCE(T1.arch_tape_date, '1958-01-01 00:00:00'), COALESCE(T1.safe_tape, 'N/A'), COALESCE(T1.safe_tape_fn, 0), COALESCE(T1.safe_tape_date, '1958-01-01 00:00:00'), COALESCE(T2.effective_date, '195801010000'), coalesce(T2.status, 0), coalesce(T2.archive_substatus, 0) FROM " + SUM_MAIN + " AS T1 LEFT OUTER JOIN " + SUM_PARTN_ALLOC + " AS T2 ON (T1.ds_index = T2.ds_index) WHERE T1.ds_index IN (" + ','.join(self.request.data.sulist) + ')'
        self.exeDbCmd()
        dbInfo.append(self.dbRes)
        self.parse(dbInfo)

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(InfoResponse, self)._createRspDict()

        if not 'suinfo' in self.rspDict:
            self.rspDict['suinfo'] = copy.deepcopy(self.data['suinfo'])

            # convert all 64-bit numbers from hex string to integers
            for infoDict in self.rspDict['suinfo']:
                infoDict['sunum'] = Request.hexToInt(infoDict['sunum'])
                infoDict['bytes'] = Request.hexToInt(infoDict['bytes'])

    def parse(self, dbInfo):
        infoList = []
        processed = {}

        # Make an object from the lists returned by the database. dbResponse is a list of lists.
        for row in dbInfo[0]:
            rowIter = iter(row)
            infoDict = {}
            sunum = next(rowIter)
            infoDict['sunum'] = Response.intToHex(sunum) # Convert to hex string since some parsers do not support 64-bit integers.
            infoDict['onlineLoc'] = next(rowIter)
            infoDict['onlineStatus'] = next(rowIter)
            infoDict['archiveStatus'] = next(rowIter)
            infoDict['offsiteAck'] = next(rowIter)
            infoDict['historyComment'] = next(rowIter)
            infoDict['owningSeries'] = next(rowIter)
            infoDict['storageGroup'] = next(rowIter)
            infoDict['bytes'] = Response.intToHex(next(rowIter)) # Convert to hex string since some parsers do not support 64-bit integers.
            infoDict['createSumid'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['creatDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['username'] = next(rowIter)
            infoDict['archTape'] = next(rowIter)
            infoDict['archTapeFn'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['archTapeDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['safeTape'] = next(rowIter)
            infoDict['safeTapeFn'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['safeTapeDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['effectiveDate'] = next(rowIter)
            infoDict['paStatus'] = next(rowIter)
            infoDict['paSubstatus'] = next(rowIter)

            # Put SU in hash of processed SUs.
            suStr = str(sunum) # Convert hexadecimal string to decimal string.
            processed[suStr] = infoDict

        # Loop through ALL SUs, even duplicates (the sus list may contain duplicates).
        for su in self.request.data.sus:
            if str(su) in processed:
                infoList.append(processed[str(su)])
            else:
                # Must check for an invalid SU and set some appropriate values if the SU is indeed invalid:
                #   sunum --> sunum
                #   paStatus --> 0
                #   paSubstatus --> 0
                #   onlineLoc --> ''
                #   effectiveDate --> 'N/A'
                # The other attributes do not matter.
                # If the SUNUM was invalid, then there was no row in the response for that SU. So, we
                # have to create dummy rows for those SUs.
                infoDict = {}
                infoDict['sunum'] = Response.intToHex(su) # Convert to hex string since some parsers do not support 64-bit integers.
                infoDict['onlineLoc'] = ''
                infoDict['onlineStatus'] = ''
                infoDict['archiveStatus'] = ''
                infoDict['offsiteAck'] = ''
                infoDict['historyComment'] = ''
                infoDict['owningSeries'] = ''
                infoDict['storageGroup'] = -1
                infoDict['bytes'] = Response.intToHex(0) # In sum_main, bytes is a 64-bit integer. In SUM_info, it is a double. sum_open.c converts the integer (long) to a floating-point number.
                infoDict['createSumid'] = -1
                infoDict['creatDate'] = '1966-12-25 00:54'
                infoDict['username'] = ''
                infoDict['archTape'] = ''
                infoDict['archTapeFn'] = -1
                infoDict['archTapeDate'] = '1966-12-25 00:54'
                infoDict['safeTape'] = ''
                infoDict['safeTapeFn'] = -1
                infoDict['safeTapeDate'] = '1966-12-25 00:54'
                infoDict['effectiveDate'] = 'N/A'
                infoDict['paStatus'] = 0
                infoDict['paSubstatus'] = 0

                infoList.append(infoDict)

        self.data['suinfo'] = infoList

    def undo(self):
        # all DB changes will be rolled back on error, so nothing to do here;
        # plus this call does not modify the DB
        pass


class GetResponse(Response):
    def __init__(self, request, status, dest=None):
        super(GetResponse, self).__init__(request, status)

        # Extract response data from the DB.
        dbInfo = []
        self.dbRes = []
        # sum_main query first. The DB response will be used to generate the SUM_get() response.
        self.cmd = 'SELECT T1.ds_index, T1.online_loc, T1.online_status, T1.archive_status, T1.arch_tape, T1.arch_tape_fn FROM ' + SUM_MAIN + ' AS T1 WHERE ds_index IN (' + ','.join(self.request.data.susNoDupes) + ')'
        self.exeDbCmd()
        dbInfo.append(self.dbRes)

        self.parse(dbInfo)

        if dest:
            dest.data['supaths'] = self.data['supaths']

        # SUM_get() has a side effect: if the SU is online, then we update the retention, otherwise, we read the SU from tape (if the
        # DRMS has a tape system).

        # sum_partn_alloc UPDATE query second. This is one side-effect of the SUM_get(). It potentially modifies the effective_date of the
        # SUs.
        if self.request.data.touch:
            if self.request.data.retention < 0:
                # If the retention value is negative, then set the effective_date to max(today + -retention, current effective date).
                # The effective_date is a DB string - a string! It has the format YYYYMMDDHHMM - no time zone. Use DB's timestamp
                # functions to use math on effective_date.
                #
                # A status of 8 implies a read-only SU. Add "3 days grace".
                # susNoDupes does not contain duplicates.
                self.cmd = 'UPDATE ' + SUM_PARTN_ALLOC + " AS T1 SET effective_date = to_char(CURRENT_TIMESTAMP + interval '" + str(-self.request.data.retention + 3) + " days', 'YYYYMMDDHH24MI') FROM " + SUM_MAIN + " AS T2 WHERE T1.status != 8 AND (T1.effective_date = '0' OR CURRENT_TIMESTAMP + interval '" + str(-self.request.data.retention) + " days' >  to_timestamp(T1.effective_date, 'YYYYMMDDHH24MI')) AND T1.ds_index IN (" + ','.join(self.request.data.susNoDupes) + ") AND T1.ds_index = T2.ds_index AND T2.online_status = 'Y'"
            else:
                # Set the effective date to today + retention.
                self.cmd = 'UPDATE ' + SUM_PARTN_ALLOC + " AS T1 SET effective_date = to_char(CURRENT_TIMESTAMP + interval '" + str(self.request.data.retention + 3) + " days', 'YYYYMMDDHH24MI') FROM " + SUM_MAIN + " AS T2 WHERE T1.status != 8 AND T1.ds_index IN (" + ','.join(self.request.data.susNoDupes) + ") AND T1.ds_index = T2.ds_index AND T2.online_status = 'Y'"

            self.exeDbCmdNoResult()

        # Tape read. Send a request to the tape system for all SUs that have the readfromtape attribute.
        tapeRequest = {}
        for sunum in self.info:
            if self.info[str(sunum)]['readfromtape']:
                # Insert the SUNUM, the tape ID, and the tape file number into a contain to be passed to the tape service.
                tapeRequest[str(sunum)] = { 'tapeid' : self.info[str(sunum)]['tapeid'], 'tapefn' : self.info[str(sunum)]['tapefn'] }

        if len(tapeRequest) > 0:
            self.data['taperead-requestid'] = uuid.uuid1()
            if dest:
                dest.data['taperead-requestid'] = self.data['taperead-requestid']

            # Make tape-service request. NOT IMPLEMENTED!
            raise ImplementationException('SUMS is configured to provide tape service, but the tape service is not implemented')

            # Spawn a thread to process the tape-read request. Store the thread ID and a status, initially 'pending', in a hash array
            # in a class variable of the TapeRequestClient class. The key for this hash-array entry is the taperead-requestid value.
            # When the TapeRequest thread completes successfully, the thread ID of the entry is set to None. The status is
            # either set to success or failure. The PollRequest looks for the entry in the hash array. If it does not find it,
            # the PollRequest errors out. If it finds it, it then it looks at the status. If it is 'pending', then the PollRequest
            # code returns the taperead-requestid back to the client. If the status is 'complete', then the PollRequest
            # code returns a valid GetResponse formed from the information returned from the tape service.
            # tapeRequestClient = TapeRequestClient(self.data['taperead-requestid'], self.request)

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(GetResponse, self)._createRspDict()

        if not 'supaths' in self.rspDict:
            self.rspDict['supaths'] = copy.deepcopy(self.data['supaths'])

            # convert all 64-bit numbers from hex string to integers
            for suPathDict in self.rspDict['supaths']:
                suPathDict['sunum'] = Request.hexToInt(suPathDict['sunum'])

    def parse(self, dbInfo):
        supaths = []
        processed = {}
        self.info = {}

        for row in dbInfo[0]:
            rowIter = iter(row)
            suPathDict = {}

            sunum = next(rowIter)
            self.info[str(sunum)] = {}
            self.info[str(sunum)]['path'] = next(rowIter)

            # Save the online and archive status for side-effect changes.
            self.info[str(sunum)]['online'] = (next(rowIter).lower() == 'y')
            self.info[str(sunum)]['archived'] = (next(rowIter).lower() == 'y')
            self.info[str(sunum)]['tapeid'] = next(rowIter) # String
            self.info[str(sunum)]['tapefn'] = next(rowIter) # Integer

            suPathDict['sunum'] = Response.intToHex(sunum) # Convert to hex string since some parsers do not support 64-bit integers.
            # Gotta deal with offline SUs. Despite the fact these are offline, SUM_MAIN::online_loc has a path. We need to remove that path.
            if self.info[str(sunum)]['online']:
                suPathDict['path'] = self.info[str(sunum)]['path']
                self.info[str(sunum)]['readfromtape'] = False
            else:
                suPathDict['path'] = None
                if not self.request.data.retrieve:
                    self.info[str(sunum)]['readfromtape'] = False
                else:
                    # If the DRMS does not have a tape system, then archive_status should never be anything other than 'N'. But
                    # just to be sure, check the tape-system attribute of SUMS.
                    if self.request.worker.has_tape_sys and self.info[str(sunum)]['archived']:
                        self.info[str(sunum)]['readfromtape'] = True
                    else:
                        self.info[str(sunum)]['readfromtape'] = False

            if str(sunum) not in processed:
                processed[str(sunum)] = suPathDict

        # sus may contain duplicates.
        for su in self.request.data.sus:
            if str(su) in processed:
                supaths.append(processed[str(su)])
            else:
                # Set the path to the None for all invalid/unknown SUs.
                suPathDict = {}
                suPathDict['sunum'] = Response.intToHex(su)
                suPathDict['path'] = None

                supaths.append(suPathDict)

        # To send to client.
        self.data['supaths'] = supaths

    def undo(self):
        # all DB changes will be rolled back on error, so nothing to do here;
        # plus this call does not modify the DB
        pass

class AllocResponse(Response):
    def __init__(self, request, status, dest=None):
        super(AllocResponse, self).__init__(request, status)

        partSet = 0

        # a SUMS "partition set" is a group of partitions; SUMS installations can have either a single partition
        # set, or multiple sets; when allocating an SU dir on a partition in a multi-partition system,
        # one partition must be selected; a partition set is a way of restricting which partitions are available
        # for SU allocation; the SU group is mapped to a partition set, and then an partition is chosen from
        # that set for allocation; this mapping is defined by the SUMS DB table SUM_ARCH_GROUP - the group number
        # is mapped to a partition set id (an integer)
        #
        # for a system with a single partition set, the partition set has an id of 0
        if self.request.worker.has_mult_part_sets:
            if hasattr(self.request.data, 'sugroup'):
                self.dbRes = []
                self.cmd = 'SELECT sum_set FROM ' + SUM_ARCH_GROUP + ' WHERE group_id = ' + str(self.request.data.sugroup)
                self.exeDbCmd()

                if len(self.dbRes) != 1 or len(self.dbRes[0]) != 1:
                    raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

                partSet = self.dbRes[0][0]

        # we used to choose for allocation a partition that had sufficient room by reading the avail_bytes column from
        # the SUM_PARTN_AVAIL table of the SUMS DB; however, this column gets updated only when sum_rm is run, and it
        # isn't always the case that sum_rm gets run, so this value could be stale or inaccurate; instead, sumsd.py and
        # su-stewie.py (the sum_rm replacement) do not use either the avail_bytes or total_bytes (in fact, no part
        # of SUMS ever reads the value for total_bytes)
        #
        # instead, call the statfs() system call to ensure that a partition exists with at least self.request.data.numbytes
        # available (not that anybody who calls SUM_alloc() ever provides an accurate estimate of the number of bytes needed);
        # we need to call either df or os.statvfs(), both call the statfs system call; however, since statfs can hang with NFS-
        # mounted drives, we need to call statfs() in a different process - calling it from a thread is not good enough
        # since this could lead to a hung thread, and attempting to kill a thread is not advisable and could lead to
        # unpredictable behavior
        self.dbRes = []
        self.cmd = 'SELECT partn_name FROM ' + SUM_PARTN_AVAIL + ' WHERE pds_set_num = ' + str(partSet)
        self.exeDbCmd()

        if len(self.dbRes) < 1:
            raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

        partitions = []
        for row in self.dbRes:
            if len(row) != 1:
                raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

            # for each partition, find out how much free space exists; if we cannot find out how much free space exists
            # cause the os.statvfs command hung, then remove this partition from consideration
            lock = Lock()
            availBytes = Value(c_longlong, 0, lock=lock)
            proc = Process(target=AllocResponse.__callStatvfs, args=(row[0], availBytes))
            proc.start()
            proc.join(2) # timeout after 2 seconds

            if proc.exitcode is None:
                self.request.worker.log.write_warning([ 'os.statvfs(' + row[0] + ') did not terminate; skipping partition' ])
                proc.terminate()
                continue

            if availBytes.value >= self.request.data.numbytes:
                self.request.worker.log.write_debug([ 'partition ' + row[0] + ' has sufficient disk space; added to available list' ])
                partitions.append(row[0])

        # if the request contains a SUNUM, then that SUNUM becomes the id of the SU being allocated; otherwise,
        # the next id in the sequence is chosen
        if hasattr(self.request.data, 'sunum'):
            sunum = self.request.data.sunum
        else:
            self.dbRes = []
            self.cmd = "SELECT nextval('public.sum_ds_index_seq')"
            self.exeDbCmd()

            if len(self.dbRes) != 1 or len(self.dbRes[0]) != 1:
                raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

            sunum = self.dbRes[0][0]

        # Randomly choose one of the partitions to put the new SU into. We want to spread the write load over available
        # partitions.
        randIndex = random.randint(0, len(partitions) - 1)
        partition = partitions[randIndex]
        self.request.worker.log.write_debug([ 'partition ' + partition + ' was randomly chosen to satisfy allocation request' ])
        sudir = os.path.join(partition, 'D' + str(sunum))

        try:
            os.mkdir(sudir)
            os.chmod(sudir, 0O2775)

            # Insert a record into the sum_partn_alloc table for this SU. status is DARW, which is 1. effective_date is "0". arch_sub is 0. group_id is 0. safe_id is 0. ds_index is 0.
            self.cmd = 'INSERT INTO ' + SUM_PARTN_ALLOC + "(wd, sumid, status, bytes, effective_date, archive_substatus, group_id, safe_id, ds_index) VALUES ('" + sudir + "', '" + str(self.request.data.sessionid) + "', " + str(DARW) + ", " + str(self.request.data.numbytes) + ", '0', 0, 0, 0, 0)"
            self.exeDbCmdNoResult()

            # To send to client.
            self.data['sunum'] = Response.intToHex(sunum)
            self.data['sudir'] = sudir
        except:
            # ok, undo the mkdir
            if not 'sudir' in self.data:
                self.data['sudir'] = sudir
            self.undo()
            raise # could be on OSError or an

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(AllocResponse, self)._createRspDict()

        if not 'sunum' in self.rspDict:
            self.rspDict['sunum'] = Request.hexToInt(self.data['sunum'])

        if not 'sudir' in self.rspDict:
            self.rspDict['sudir'] = self.data['sudir']

    def undo(self):
        # all DB changes will be rolled back on error, so no DB changes to do here;
        # but there were filesys changes that have to be undone
        if os.path.exists(self.data['sudir']):
            shutil.rmtree(self.data['sudir'])
        self.request.worker.log.write_debug([ 'undid alloc mkdir for client ' + str(self.request.worker.getID()) ])

    @classmethod
    def __callStatvfs(cls, suPartitionPath, rv):
        fsStats = os.statvfs(suPartitionPath)
        if fsStats is not None and hasattr(fsStats, 'f_bsize') and hasattr(fsStats, 'f_bavail'):
            rv.value = fsStats.f_bsize * fsStats.f_bavail

class SUFileOwnerModUpdater(object):
    _updater_lock = None
    _updater_lock_path = None
    _updater_lock_type = None
    _thread_lock = threading.Lock()

    def __init__(self, log=None):
        if self._updater_lock is None:
            raise SUFileOwnerModUpdaterException('cannot instantiate updater for ' + self.__class__.__name__ + '; lock file not set')

        self._log = log
        if self._log:
            log.write_debug([ '[ SUFileOwnerModUpdater.__init__ ] creating {updater_type} updater'.format(updater_type=str(self)) ])

    def __str__(self):
        return self.__class__.__name__

    @classmethod
    def set_lock_file(cls, *, lock_path, type):
        # create lock file so that only one sum_chmown at a time, or one user editing put_file in 10 seconds
        if lock_path is not None:
            cls._updater_lock = DrmsLock(lock_path, None, True) # None ==> do not automatically write content to file, True ==> retry 10 times
        else:
            self._updater_lock = None
        cls._updater_lock_path = lock_path
        cls._updater_lock_type = type

    @classmethod
    def acquire_thread_lock(cls):
        if cls._thread_lock:
            cls._thread_lock.acquire()

    @classmethod
    def release_thread_lock(cls):
        if cls._thread_lock:
            cls._thread_lock.release()

    @classmethod
    def create_updater(cls, worker):
        if worker.log:
            worker.log.write_debug([ '[ SUFileOwnerModUpdater.create_updater ]'])
        if cls._updater_lock_type == 'put':
            return PutFileUpdater(log=worker.log)
        elif cls._updater_lock_type == 'chmown':
            return SumChmownUpdater(chmown_path=worker.chmown_path, log=worker.log)
        else:
            return NoopSuFileUpdater(log=worker.log)

class NoopSuFileUpdater(SUFileOwnerModUpdater):
    def __init__(self, *, log=None):
        self._log = log
        if self._log:
            log.write_debug([ '[ NoopSuFileUpdater.__init__ ] creating {updater_type} updater'.format(updater_type=str(self)) ])

        self._chmown_path = None

    def update(self, su_path):
        # noop - do not do anthing with SU file owner or perms
        pass


class SumChmownUpdater(SUFileOwnerModUpdater):
    def __init__(self, *, chmown_path, log=None):
        super(SumChmownUpdater, self).__init__(log)
        self._chmown_path = chmown_path

    def update(self, su_path):
        # we are inside thread lock
        cmd_list = [ self._chmown_path, su_path ]

        self._updater_lock.acquireLock() # file lock
        try:
            self._log.write_debug([ '[ SumChmownUpdater.update ] running {cmd}'.format(cmd=' '.join(cmd_list)) ])
            check_call(cmd_list)
        except CalledProcessError as exc:
            raise SumsChmownException('failure calling ' +  self.sum_chmown_path)
        finally:
            self._updater_lock.releaseLock()
            self._updater_lock.close(False)

class PutFileUpdater(SUFileOwnerModUpdater):
    def __init__(self, log=None):
        super(PutFileUpdater, self).__init__(log)

    def update(self, su_path):
        # we are inside thread lock
        # write to tmp file in case we cannot acquire lock; then the next time lock IS acquired, copy from tmp file to lock file
        write_to_tmp = False
        try:
            dir, file = os.path.split(self._updater_lock_path)
            tmp_file = os.path.join(dir, '.' + file)
            self._log.write_debug([ '[ PutFileUpdater.update ] acquiring updater lock' ])
            self._updater_lock.acquireLock()
            try:
                # lock file is open for appending
                if os.path.exists(tmp_file):
                    self._log.write_debug([ '[ PutFileUpdater.update ] temporary put file {tmp_file} exists; copying to put file {lock_file}'.format(tmp_file=tmp_file, lock_file=self._updater_lock_path) ])
                    # a tmp file exists; we have the lock now, so write its contents to the lock file
                    with open(tmp_file, mode='r') as fin:
                        for block in iter(partial(fin.read, 1024), ''):
                            # block is text; write SU to lock file
                            self._updater_lock.write_to_file(block)

                    # delete the tmp file
                    unlink(tmp_file)

                # now write current SU to lock file
                self._log.write_debug([ '[ PutFileUpdater.update ] writing SU {su} to {lock_file}'.format(su=su_path, lock_file=self._updater_lock_path) ])
                self._updater_lock.write_to_file(su_path + '\n')
            except OSError as exc:
                raise PutFileException('[ PutFileUpdater.update ] error updating SUMS put file `{exc_msg}`'.format(exc_msg=str(exc)))

            finally:
                self._updater_lock.releaseLock()
                self._updater_lock.close(False)
        except Exception as error:
            if len(error.args) == 2:
                type, msg = error
                if type == 'drmsLock':
                    # could not obtain lock (after trying for 10 seconds); write to tmp file
                    write_to_tmp = True
                else:
                    raise
            else:
                raise

        if write_to_tmp:
            try:
                with open(tmp_file, mode='a') as f_tmp:
                    tmp_file.write(su_path + '\n')
            except OSError as exc:
                raise PutFileException('[ PutFileUpdater.update ] error updating SUMS tmp put file `{exc_msg}`'.format(exc_msg=str(exc)))

class PutResponse(Response):
    def __init__(self, request, status, dest=None):
        super(PutResponse, self).__init__(request, status)

        self._file_owner_mod_updater = SUFileOwnerModUpdater.create_updater(self.request.worker)

        try:
            # We have to change ownership of the SU files to the production user - ACK! This is really bad design. It seems like
            # the only solution without a better design is to call an external program that runs as setuid root. This program calls
            # chown recursively. It also make files read-only by calling chmod on all regular files.

            # Save a mapping from SUDIR to SUNUM.
            sunums = {}

            partitionsNoDupes = set()
            for elem in self.request.data.sudirsNoDupes:
                [(suStr, path)] = elem.items()
                partition = os.path.dirname(path)
                partitionsNoDupes.add(partition)
                sunums[path] = suStr

            # sum_chmown does not do a good job of preventing the caller from changing ownership of an arbitrary
            # directory, so add a little more checking here. Make sure that all partitions containing the SUs being committed
            # are valid SUMS partitions.
            self.dbRes = []
            self.cmd = 'SELECT count(*) FROM ' + SUM_PARTN_AVAIL + " WHERE rtrim(partn_name, '/') IN (" + ','.join([ "'" + partition + "'" for partition in partitionsNoDupes] ) + ')'
            self.exeDbCmd()

            if len(self.dbRes) != 1 or len(self.dbRes[0]) != 1:
                raise DBCommandException('unexpected DB response to cmd: ' + self.cmd)

            if self.dbRes[0][0] != len(partitionsNoDupes):
                self.request.worker.log.write_debug([ 'number of unique partitions in request: ' + str(len(partitionsNoDupes)), 'number of matching partitions in DB: ' + str(self.dbRes[0][0])] )
                raise ArgsException('one or more invalid paritition paths')

            if self.request.worker.has_tape_sys:
                apStatus = DAAP
            else:
                apStatus = DADP

            # This horrible program operates on a single SU at a time, so we have to call it in a loop.
            sudirs = []
            sus = []
            for elem in self.request.data.sudirsNoDupes:
                [(suStr, path)] = elem.items()
                sudirs.append(path)
                sus.append(suStr)

                if self._file_owner_mod_updater is not None:
                    self.request.worker.log.write_debug([ '[ PutResponse.__init__ ] calling SU ownership/privs updater' ])
                    # must acquire thread lock since update() will acquire file lock
                    self._file_owner_mod_updater.acquire_thread_lock()
                    try:
                        self._file_owner_mod_updater.update(path)
                    finally:
                        self._file_owner_mod_updater.release_thread_lock()

            # If all file permission and ownership changes succeed, then commit the SUs to the SUMS database.

            # The tape group was determined during the SUM_alloc() call and is now stored in SUM_PARTN_ALLOC (keyed by wd NOT ds_index).
            # The JMD calls alloc in one SUMS session, and put in another. When this happens, the row in SUM_PARTN_ALLOC
            # gets deleted at the end of the first session, during the close call. So, the group information is lost. The JMD
            # calls SUM_alloc2() directly, so the group never gets set in the SUMS struct. Since the SUMS struct is
            # zeroed-out when it is allocated during SUM_open(), the group ends up being 0.
            storageGroup = {} # Map SUNUM to storage group.
            allStorageGroups = set()

            # default to group 0 if there is no row in sum_partn_alloc for any sunum
            for sudir in sudirs:
                storageGroup[sunums[sudir]] = 0
            allStorageGroups.add(str(0))

            self.dbRes = []
            # Ugh. SUMS does not insert the SUNUM during the SUM_alloc() call. It sets ds_index to 0. Use wd as the key.
            self.cmd = 'SELECT wd, group_id FROM ' + SUM_PARTN_ALLOC + ' WHERE wd IN (' +  ','.join([ "'" + sudir + "'" for sudir in sudirs ]) + ')'
            self.exeDbCmd()

            if len(self.dbRes) != 0:
                # for the JMD, len(self.dbRes) == 0 (all the sum_partn_alloc rows were deleted); otherwise,
                # len(self.dbRes) == len(sudirs); map the wd to group for all present rows
                for row in self.dbRes:
                    # map sunum to group
                    storageGroup[sunums[row[0]]] = row[1]
                    if str(row[1]) not in allStorageGroups:
                        allStorageGroups.add(str(row[1]))

            storageSet = {} # Map storage group to storage set.
            for group in allStorageGroups:
                # default to storage set 0 for all groups
                storageSet[group] = 0

            if self.request.worker.has_mult_part_sets:
                self.dbRes = []
                self.cmd = 'SELECT group_id, sum_set FROM ' + SUM_ARCH_GROUP + ' WHERE group_id IN (' + ','.join(allStorageGroups) + ')'
                self.exeDbCmd()

                # Override the mapping to 0
                if len(self.dbRes) > 0:
                    for row in self.dbRes:
                        # map group to storage set
                        storageSet[str(row[0])] = row[1]

            # Update SUMS sum_main database table - Calculate SU dir number of bytes, set online status to 'Y', set archstatus to 'N',
            # set offsiteack to 'N', set dsname to seriesname, set storagegroup to tapegroup (determined in SUM_alloc()), set storageset
            # to set determined in SUM_alloc(), set username to getenv('USER') or nouser if no USER env. Insert all of this into sum_main.
            suSize = {}
            for elem in self.request.data.sudirsNoDupes:
                [(suStr, path)] = elem.items()
                resolved = os.path.realpath(path)
                numBytes = os.path.getsize(resolved) + sum([ os.path.getsize(fullPath) for fullPath in [ os.path.join(root, afile) for root, dirs, files in os.walk(resolved) for afile in files ] ]) + sum([ os.path.getsize(fullPath) for fullPath in [ os.path.join(root, adir) for root, dirs, files in os.walk(resolved) for adir in dirs ] ])
                # Need to use to save this number into SUM_PARTN_ALLOC too.
                suSize[suStr] = numBytes

                self.cmd = 'INSERT INTO ' + SUM_MAIN + "(online_loc, online_status, archive_status, offsite_ack, history_comment, owning_series, storage_group, storage_set, bytes, ds_index, create_sumid, creat_date, access_date, username) VALUES ('" + path + "', 'Y', 'N', 'N', '', '" + self.request.data.series + "', " + str(storageGroup[suStr]) + ', ' + str(storageSet[str(storageGroup[suStr])]) + ', ' + str(numBytes) + ', ' + suStr + ', ' + str(self.request.data.sessionid) + ", localtimestamp, localtimestamp, '" + os.getenv('USER', 'nouser') + "')"
                self.exeDbCmdNoResult()

            if apStatus == DADP:
                # We do this simply to ensure that we do not have two sum_partn_alloc records with status DADP (delete pending).
                self.cmd = 'DELETE FROM ' + SUM_PARTN_ALLOC + ' WHERE ds_index IN (' + ','.join(sus) + ') AND STATUS = ' + str(DADP)
                self.exeDbCmdNoResult()

            # Set apstatus: if SUMS_TAPE_AVAILABLE ==> DAAP (4), else DADP (2), set archsub to one of DAAPERM, DAAEDDP, or DAADP,
            # depending on flags, set effective_date to tdays in the future (with format "%04d%02d%02d%02d%02d"). safe_id is 0
            # (it looks obsolete). Insert all of this into sum_partn_alloc.
            if self.request.data.archivetype == 'permanent+archive' and self.request.worker.has_tape_sys:
                archsub = DAAPERM
            elif self.request.data.archivetype == 'temporary+noarchive':
                archsub = DAAEDDP
            elif self.request.data.archivetype == 'temporary+archive' and self.request.worker.has_tape_sys:
                archsub = DAADP
            else:
                archsub = DAAEDDP

            for elem in self.request.data.sudirsNoDupes:
                [(suStr, path)] = elem.items()
                self.cmd = 'INSERT INTO ' + SUM_PARTN_ALLOC + "(wd, sumid, status, bytes, effective_date, archive_substatus, group_id, safe_id, ds_index) VALUES ('" + path + "', " + str(self.request.data.sessionid) + ', ' + str(apStatus) + ', ' + str(suSize[suStr]) + ", to_char(CURRENT_TIMESTAMP + interval '" + str(abs(self.request.data.retention)) + " days', 'YYYYMMDDHH24MI'), " + str(archsub) + ', ' + str(storageGroup[suStr]) + ', 0, ' + suStr + ')'
                self.exeDbCmdNoResult()

            # To send to client.
            # Just 'ok'.
        except:
            # We have to clean up db rows that were created in SUM_alloc() and SUM_put(). The SUM_alloc() request was processed in
            # a previous DB transaction, so it will have been committed by this point. Then re-raise so an error response is generated.

            # Undo SUM_alloc() insertions.
            self.cmd = 'DELETE FROM ' + SUM_PARTN_ALLOC + ' WHERE ds_index IN (' + ','.join(sus) + ')'
            self.exeDbCmdNoResult()

            self.cmd = 'DELETE FROM ' + SUM_MAIN + ' WHERE ds_index IN (' + ','.join(sus) + ')'
            self.exeDbCmdNoResult()

            raise

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(PutResponse, self)._createRspDict()

    def undo(self):
        # all DB changes will be rolled back on error, so no DB changes to do here;
        # but sum_chmown was called - ugh, punt!
        pass


class DeleteseriesResponse(Response):
    def __init__(self, request, status, dest=None):
        super(DeleteseriesResponse, self).__init__(request, status)

        series = self.request.data.series.lower()

        # This update/join is a very quick operation. And if the series has no records, it is a quick noop.
        self.cmd = 'UPDATE ' + SUM_PARTN_ALLOC + ' AS T1 SET status = ' + str(DADP) + ", effective_date = '0', archive_substatus = " + str(DAADP) + ' FROM ' + SUM_MAIN + " AS T2 WHERE lower(T2.owning_series) = '" + series + "' AND T1.ds_index = T2.ds_index"
        self.exeDbCmdNoResult()

        # To send to client.
        # Just 'ok'.

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(DeleteseriesResponse, self)._createRspDict()

    def undo(self):
        # all DB changes will be rolled back on error, so no DB changes to do here
        pass

class InfoResponseOLD(Response):
    def __init__(self, request, status, dest=None):
        super(InfoResponseOLD, self).__init__(request, status)

        # Extract response data from the DB.
        dbInfo = [] # In theory there could be multiple DB requests.
        self.dbRes = []
        # Get DB info for unique SUs only (the sulist list does not contain duplicates).
        self.cmd = "SELECT T1.ds_index, T1.online_loc, T1.online_status, T1.archive_status, T1.offsite_ack, T1.history_comment, T1.owning_series, T1.storage_group, T1.bytes, T1.create_sumid, T1.creat_date, T1.username, COALESCE(T1.arch_tape, 'N/A'), COALESCE(T1.arch_tape_fn, 0), COALESCE(T1.arch_tape_date, '1958-01-01 00:00:00'), COALESCE(T1.safe_tape, 'N/A'), COALESCE(T1.safe_tape_fn, 0), COALESCE(T1.safe_tape_date, '1958-01-01 00:00:00'), COALESCE(T2.effective_date, '195801010000'), coalesce(T2.status, 0), coalesce(T2.archive_substatus, 0) FROM " + SUM_MAIN + " AS T1 LEFT OUTER JOIN " + SUM_PARTN_ALLOC + " AS T2 ON (T1.ds_index = T2.ds_index) WHERE T1.ds_index IN (" + ','.join(self.request.data.sulist) + ')'
        self.exeDbCmd()
        dbInfo.append(self.dbRes)
        self.parse(dbInfo)

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(InfoResponse, self)._createRspDict()

        if not 'suinfo' in self.rspDict:
            self.rspDict['suinfo'] = copy.deepcopy(self.data['suinfolist'])

            # convert all 64-bit numbers from hex string to integers
            for infoDict in self.rspDict['suinfo']:
                infoDict['sunum'] = Request.hexToInt(infoDict['sunum'])
                infoDict['bytes'] = Request.hexToInt(infoDict['bytes'])

    def parse(self, dbInfo):
        infoList = []
        processed = {}

        # Make an object from the lists returned by the database. dbResponse is a list of lists.
        for row in dbInfo[0]:
            rowIter = iter(row)
            infoDict = {}
            sunum = next(rowIter)
            infoDict['sunum'] = Response.intToHex(sunum) # Convert to hex string since some parsers do not support 64-bit integers.
            infoDict['onlineLoc'] = next(rowIter)
            infoDict['onlineStatus'] = next(rowIter)
            infoDict['archiveStatus'] = next(rowIter)
            infoDict['offsiteAck'] = next(rowIter)
            infoDict['historyComment'] = next(rowIter)
            infoDict['owningSeries'] = next(rowIter)
            infoDict['storageGroup'] = next(rowIter)
            infoDict['bytes'] = Response.intToHex(next(rowIter)) # Convert to hex string since some parsers do not support 64-bit integers.
            infoDict['createSumid'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['creatDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['username'] = next(rowIter)
            infoDict['archTape'] = next(rowIter)
            infoDict['archTapeFn'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['archTapeDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['safeTape'] = next(rowIter)
            infoDict['safeTapeFn'] = next(rowIter)
            # The db returns a datetime object. Convert the datetime to a str object.
            infoDict['safeTapeDate'] = next(rowIter).strftime('%Y-%m-%d %T')
            infoDict['effectiveDate'] = next(rowIter)
            infoDict['paStatus'] = next(rowIter)
            infoDict['paSubstatus'] = next(rowIter)

            # Put SU in hash of processed SUs.
            suStr = str(sunum) # Convert hexadecimal string to decimal string.
            processed[suStr] = infoDict

        # Loop through ALL SUs, even duplicates (the sus list may contain duplicates).
        for su in self.request.data.sus:
            if str(su) in processed:
                infoList.append(processed[str(su)])
            else:
                # Must check for an invalid SU and set some appropriate values if the SU is indeed invalid:
                #   sunum --> sunum
                #   paStatus --> 0
                #   paSubstatus --> 0
                #   onlineLoc --> ''
                #   effectiveDate --> 'N/A'
                # The other attributes do not matter.
                # If the SUNUM was invalid, then there was no row in the response for that SU. So, we
                # have to create dummy rows for those SUs.
                infoDict = {}
                infoDict['sunum'] = Response.intToHex(su) # Convert to hex string since some parsers do not support 64-bit integers.
                infoDict['onlineLoc'] = ''
                infoDict['onlineStatus'] = ''
                infoDict['archiveStatus'] = ''
                infoDict['offsiteAck'] = ''
                infoDict['historyComment'] = ''
                infoDict['owningSeries'] = ''
                infoDict['storageGroup'] = -1
                infoDict['bytes'] = Response.intToHex(0) # In sum_main, bytes is a 64-bit integer. In SUM_info, it is a double. sum_open.c converts the integer (long) to a floating-point number.
                infoDict['createSumid'] = -1
                infoDict['creatDate'] = '1966-12-25 00:54'
                infoDict['username'] = ''
                infoDict['archTape'] = ''
                infoDict['archTapeFn'] = -1
                infoDict['archTapeDate'] = '1966-12-25 00:54'
                infoDict['safeTape'] = ''
                infoDict['safeTapeFn'] = -1
                infoDict['safeTapeDate'] = '1966-12-25 00:54'
                infoDict['effectiveDate'] = 'N/A'
                infoDict['paStatus'] = 0
                infoDict['paSubstatus'] = 0

                infoList.append(infoDict)

        self.data['suinfolist'] = infoList


class PingResponse(Response):
    """
    As long as we can respond with an 'ok', then SUMS is up and running.
    """
    def __init__(self, request, status, dest=None):
        super(PingResponse, self).__init__(request, status)

        # To send to client.
        # Just 'ok'.

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(PingResponse, self)._createRspDict()

    def undo(self):
        pass


class PollResponse(Response):
    def __init__(self, request, status, dest=None):
        super(PollResponse, self).__init__(request, status)

        tapeRequestID = self.request.data.requestID

        # Check with TapeRequestClient class to see if request has completed.
        reqStatus = TapeRequestClient.getTapeRequestStatus(tapeRequestID)
        if reqStatus == 'pending':
            self.data['taperead-requestid'] = tapeRequestID
            self.data['status'] = RESPSTATUS_TAPEREAD
        elif reqStatus == 'complete':
            origRequest = TapeRequestClient.getOrigRequest(tapeRequestID)
            origRequest.generateResponse(self) # This will make a GetResponse (so far, you can poll for GetResponse only).
        else:
            raise TaperequestException('unexpected status returned by tape system: ' + reqStatus)

    def _stringify(self):
        if not hasattr(self, 'rspDict'):
            super(PollResponse, self)._createRspDict() # either RESPSTATUS_TAPEREAD (pending) or RESPSTATUS_OK (complete)

        if not 'reqtype' in self.rspDict:
            origRequest = TapeRequestClient.getOrigRequest(self.request.data.requestID)
            self.rspDict['reqtype'] = origRequest.reqType

        if self.data['status'] == RESPSTATUS_TAPEREAD:
            # the request is still pending
            if not 'taperead-requestid' in self.rspDict:
                self.rspDict['taperead-requestid'] = self.data['taperead-requestid']
        else:
            # need to add supaths (a list of objects)
            if not 'supaths' in self.rspDict:
                self.rspDict['supaths'] = copy.deepcopy(self.data['supaths'])

                # convert all 64-bit numbers from hex string to integers
                for suPathDict in self.rspDict['supaths']:
                    suPathDict['sunum'] = Request.hexToInt(suPathDict['sunum'])

    def undo(self):
        pass


class TapeRequestClient(threading.Thread):
    tMap = {} # Map taperead-requestid to (status, TapeRequestClient object)
    tMapLock = threading.Lock() # Guard tList access.
    maxThreads = 16

    def __init__(self, origRequest):
        self.origRequest = origRequest

    def run(self):
        # When the tape-request has completed, update the SUMS db tables, and set the request's status to 'complete'.
        pass

    @classmethod
    def getTapeRequestStatus(cls, requestID):
        status = None
        try:
            TapeRequestClient.tMapLock.acquire()
            status = cls.tMap[requestID].status
        finally:
            TapeRequestClient.tMapLock.release()

        return status

    @classmethod
    def getOrigRequest(cls, requestID):
        try:
            TapeRequestClient.tMapLock.acquire()
            origRequest = cls.tMap[requestID].tapeRequest.origRequest
        finally:
            TapeRequestClient.tMapLock.release()


class Message(object):
    '''
    '''
    MSGLEN_NUMBYTES = 8 # this is the hex-text version of the number of bytes in the response message
                        # so, we can send back 4 GB of response!
    MAX_MSG_BUFSIZE = 4096 # don't receive more than this in one call!

    def __init__(self, *, msg, sock, timeout, peer_name, log=None):
        self.msg = msg # bytes; None if receiving message
        self.sock = sock
        self.timeout = timeout # in seconds
        self.peer_name = peer_name
        self.log = log

    def send(self):
        # First send the length of the message.
        num_bytes_sent_total = 0
        num_bytes_message = '{:08x}'.format(len(self.msg))

        # time-out time
        timeout_time = datetime.now() + timedelta(seconds=self.timeout)

        # send the size of the message
        while num_bytes_sent_total < self.MSGLEN_NUMBYTES:
            if datetime.now() > timeout_time:
                raise ReceiveMsgException('timeout waiting for response from client')

            try:
                num_bytes_sent = self.sock.send(bytearray(num_bytes_message[num_bytes_sent_total:], 'UTF-8'))
                if not num_bytes_sent:
                    raise SendMsgException('socket broken - cannot send message-length data to client ' + self.peer_name)
                num_bytes_sent_total += num_bytes_sent
            except socket.timeout as exc:
                if self.log:
                    self.log.write_debug([ 'waiting for client ' + self.peer_name + ' to receive response...' ])

        # then send the actual message
        num_bytes_sent_total = 0
        while num_bytes_sent_total < len(self.msg):
            if datetime.now() > timeout_time:
                raise ReceiveMsgException('timeout waiting for response from client')

            try:
                num_bytes_sent = self.sock.send(self.msg[num_bytes_sent_total:])
                if not num_bytes_sent:
                    raise SendMsgException('socket broken - cannot send message data to client ' + self.peer_name)
                num_bytes_sent_total += num_bytes_sent
            except socket.timeout as exc:
                if self.log:
                    self.log.write_debug([ 'waiting for client ' + self.peer_name + ' to receive response...' ])

        if self.log:
            self.log.write_debug([ 'sent ' + str(num_bytes_sent_total) + ' bytes response to client ' + self.peer_name ])

    def receive(self):
        # First, receive length of message.
        all_bytes_received = b''
        num_bytes_received_total = 0

        # time-out time
        timeout_time = datetime.now() + timedelta(seconds=self.timeout)

        while num_bytes_received_total < self.MSGLEN_NUMBYTES:
            if datetime.now() > timeout_time:
                raise ReceiveMsgException('timeout waiting for response from client')

            try:
                bytes_received = self.sock.recv(min(self.MSGLEN_NUMBYTES - num_bytes_received_total, self.MAX_MSG_BUFSIZE))
                if bytes_received == b'':
                    raise ReceiveMsgException('socket broken - cannot receive message-length data from client')
                all_bytes_received += bytes_received
                num_bytes_received_total += len(bytes_received)
            except socket.timeout as exc:
                if self.log:
                    self.log.write_debug([ 'waiting for client ' + self.peer_name + ' to send request...' ])

        # Convert hex string to number.
        num_bytes_message = int(all_bytes_received.decode('UTF-8'), 16)

        # Then receive the message.
        all_bytes_received = b''
        num_bytes_received_total = 0

        while num_bytes_received_total < num_bytes_message:
            if datetime.now() > timeout_time:
                raise ReceiveMsgException('timeout waiting for response from client')

            try:
                bytes_received = self.sock.recv(min(num_bytes_message - num_bytes_received_total, self.MAX_MSG_BUFSIZE))
                if bytes_received == b'':
                    raise ReceiveMsgException('socket broken - cannot receive message data from client')
                all_bytes_received += bytes_received
                num_bytes_received_total += len(bytes_received)
            except socket.timeout as exc:
                self.log.write_debug([ 'waiting for client ' + self.peer_name + ' to send request...' ])

        if self.log:
            self.log.write_debug([ 'received ' + str(num_bytes_received_total) + ' bytes request from client ' + self.peer_name ])

        # Return a bytes object (not a string). The unjsonize function will need a str object for input.
        return all_bytes_received

# one worker instance per SUMS session (if pure MT, a session is a set of SUMS calls, otherwise it is a single call)
class Worker(threading.Thread):

    tList = [] # A list of running thread IDs.
    tListLock = threading.Lock() # Guard tList access.
    maxThreads = 32 # Default. Can be overriden with the Worker.setMaxThreads() method.
    eventMaxThreads = threading.Event() # Event fired when the number of threads decreases below threshold.

    def __init__(self, *, sock, has_tape_sys, has_mult_part_sets, timeout, chmown_path, log):
        threading.Thread.__init__(self, target=self.__run)
        # Could raise. Handle in the code that creates the thread.
        if sock is None or log is None:
            raise ArgsException('Worker thread constructor: neither sock nor log can be None')

        self.sock = sock
        self.has_tape_sys = has_tape_sys
        self.has_mult_part_sets = has_mult_part_sets
        self.client_response_timeout = timeout
        self.chmown_path = chmown_path
        self.log = log
        self.reqFactory = None
        self.msgLock = threading.Lock()
        self.messageSent = True # disable alive server until we receive a request
        self.aliveServer = None

        self.log.write_debug([ 'successfully instantiated worker for connection ' + str(self.sock.getpeername()) ])

    def __run(self):
        try:
            # this try/finally block ensures that this thread will always be removed from the thread list AND
            # it ensures that the server always closes the socket to the client
            try:
                rollback = False
                sessionOpened = False # True after opened, does not turn False after close
                sessionClosed = False # True after closed/rolled back
                clientInfoReceived = False
                pureMT = True
                history = []
                peerName = str(self.sock.getpeername()) # will raise if the socket is dead
                self.peerName = peerName

                # obtain a DB session - blocks until that happens
                self.log.write_debug([ 'client ' + peerName + ' is waiting for a DB connection' ])

                self.dbconn = DBConnection.nextOpenConnection()

                self.log.write_debug([ 'client ' + peerName + ' obtained DB connection ' + self.dbconn.getID() ])

                while True:
                    # The client must pass in some identifying information (other than their IP address).
                    # Receive that information now.
                    try:
                        if not clientInfoReceived:
                            json_string = self.receive_json() # json_string is a str
                            self.extractClientInfo(json_string)
                            clientInfoReceived = True

                        # First, obtain request.
                        json_string = self.receive_json() # json_string is a str

                        # received a new request, enable alive server
                        self.messageSent = False
                        self.extractRequest(json_string) # will raise if reqtype is not supported

                        if not self.aliveServer:
                            # we have received our first request; start AliveServer
                            self.aliveServer = AliveServer(self)
                            self.aliveServer.start() # spawn the alive-server thread; stop this thread when the worker terminates

                        if not sessionOpened and not isinstance(self.request, OpenRequest):
                            # the first request from this client not an open request, so this client is using both
                            # RPC and MT SUMS
                            pureMT = False

                        if not pureMT:
                            # if we have a mix of MT SUMS and RPC SUMS, then there are no true SUMS sessions; in this case, we
                            # want to close the session after responding now; a client is pure MT if the first call to sumsd.py
                            # is an open request; it is not allowed to configure the client such that the RPC SUMS can be used
                            # for any if the MT open request is called
                            sessionClosed = True
                        else:
                            # we have true SUMS sessions; loop through them until a close request (or rollback request) is received

                            # raise an error if there is an attempt to open a session when there is a session already opened
                            if isinstance(self.request, OpenRequest) and sessionOpened:
                                raise SessionOpenedException('cannot process a ' + self.request.getType() + ' request - a SUMS session is already open for client ' + peerName)

                            # check the request type - if not an open request and sessionOpened == False, then raise an error
                            if not isinstance(self.request, OpenRequest) and not sessionOpened:
                                raise SessionClosedException('cannot process a ' + self.request.getType() + ' request - no SUMS session is open for client ' + peerName)

                            # reject any request that follows a close request (this should never happen)
                            if sessionClosed:
                                raise SessionClosedException('cannot process a ' + self.request.getType() + ' request - the SUMS session is closed for client ' + peerName)

                            # an issue during the session caused a rollback (or the caller requests a rollback); the only allowable
                            # requests are CloseRequest and RollbackRequest
                            if rollback:
                                if not isinstance(self.request, CloseRequest) and not isinstance(self.request, RollbackRequest):
                                    raise SessionRolledbackException('cannot process a ' + self.request.getType() + ' request - the SUMS session must be closed or rolled back by client ' + peerName)

                        if self.log.log.getEffectiveLevel() == logging.INFO:
                            self.log.write_info([ 'new ' + self.request.reqType + ' request from process ' + str(self.clientInfo.data.pid) + ' by user ' + self.clientInfo.data.user + ' at ' + peerName + ':' + str(self.request) ])
                        else:
                            self.log.write_info([ 'new ' + self.request.reqType + ' request from process ' + str(self.clientInfo.data.pid) + ' by user ' + self.clientInfo.data.user + ' at ' + peerName + ':' + repr(self.request) ])

                        json_string = self.generateResponse() # a str object; generating a response can modify the DB and commit changes

                        if isinstance(self.request, OpenRequest):
                            sessionOpened = True
                        elif isinstance(self.request, CloseRequest):
                            sessionClosed = True
                        elif isinstance(self.request, RollbackRequest):
                            sessionClosed = True
                            rollback = True

                        # save for potential clean-up
                        if not isinstance(self.request, RollbackRequest):
                            history.append(self.response)
                    except SocketConnectionException as exc:
                        rollback = True

                        raise # can't send a message back to client, so terminate Worker
                    except UnjsonizerException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_JSON, str(exc))
                    except JsonizerException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_JSON, str(exc))
                    except ClientInfoException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_CLIENTINFO, str(exc))
                    except ReceiveMsgException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_MSGRECEIVE, str(exc))
                    except SendMsgException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_MSGSEND, str(exc))
                    except ExtractRequestException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_REQ, str(exc))
                    except RequestTypeException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_REQTYPE, str(exc))
                    except SessionClosedException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_SESSIONCLOSED, str(exc))
                    except SessionOpenedException as exc:
                        rollback = True
                        json_string = self.generateErrorResponse(RESPSTATUS_SESSIONOPENED, str(exc))
                    except SessionRolledbackException as exc:
                        json_string = self.generateErrorResponse(RESPSTATUS_SESSIONROLLEDBACK, str(exc))
                    except GenerateResponseException as exc:
                        rollback = True
                        self.log.write_error([ 'failure creating response' ])
                        self.log.write_error([ str(exc) ])
                        import traceback
                        self.log.write_error([ traceback.format_exc(3) ])
                        json_string = self.generateErrorResponse(RESPSTATUS_GENRESPONSE, str(exc))
                    except Exception as exc:
                        # should never get here, but in case I missed somethinig
                        rollback = True
                        import traceback
                        self.log.write_error([ traceback.format_exc(5) ])
                        json_string = self.generateErrorResponse(RESPSTATUS_SERVICEREQUEST, str(exc))

                    if hasattr(self, 'response') and self.response:
                        self.log.write_debug([ 'response:' + str(self.response) ])
                    # Send results back on the socket, which is connected to a single DRMS module. By sending the results
                    # back, the client request is completed. We want to construct a list of "SUM_info" objects. Each object
                    # { sunum:12592029, onlineloc:'/SUM52/D12592029', ...}

                    # the AliveServer thread (self.aliveServer) could send a 'im alive' - we don't want main and the worker thread
                    # stepping on each other
                    self.msgLock.acquire()
                    try:
                        self.send_json(json_string) # expects a str object; can block if the socket buffer is full (the client needs to read
                                                    # from the socket; if the client terminates, this will unblock a blocked write too)
                        self.log.write_debug([ 'sent response to ' + peerName ])
                    finally:
                        self.messageSent = True
                        self.msgLock.release()

                    if sessionClosed:
                        break
                    # end session loop

                if rollback:
                    # now we need to figure out the state of the system; a series of API calls were processed and any one of them
                    # could have failed; clean-up for the call that failed already happened, but we need to clean-up anything
                    # in the pipeline before this call that made changes to SUMS
                    for request in reversed(history):
                        request.undo()
                    self.dbconn.rollback()
                    rollback = False
                else:
                    # commit the db changes
                    self.dbconn.commit()

                # This thread is about to terminate. We don't want to end this thread before
                # the client closes the socket though. Otherwise, our socket will get stuck in
                # the TIME_WAIT state. So, perform another read, and end the thread after the client
                # has broken the connection. recv() will block till the client kills the connection
                # (or it inappropriately sends more data over the connection).
                #
                # the peer that calls close() first is the one whose socket CAN get into the TIMED_WAIT state; we
                # do not want that to happen to the server
                bytes_received = self.sock.recv(Message.MAX_MSG_BUFSIZE)
                # self.sock can be dead if the client broke the socket - getpeername() will raise; avoid using
                # it here
                if bytes_received == b'':
                    # the client closed their end of the socket (they shutdown the write half of the socket);
                    # so the client most likely called shutdown() followed by close(); however, the client could
                    # have crashed before shutting down the connection, in which case, it will implicitly be shut down
                    self.log.write_debug([ 'client ' + peerName + ' properly terminated connection' ])
                else:
                    self.log.write_debug([ 'client ' + peerName + ' sent extraneous data over socket connection (ignoring)' ])
            except SocketConnectionException as exc:
                # Don't send message back - we can't communicate with the client properly, so only log a message on the server side.
                self.log.write_error([ 'there was a problem communicating with client ' + peerName ])
                self.log.write_error([ str(exc) ])
                rollback = True
            except SendMsgException as exc:
                # Don't send message back - we can't communicate with the client properly, so only log a message on the server side.
                self.log.write_error([ 'there was a problem communicating with client ' + peerName ])
                self.log.write_error([ str(exc) ])
                rollback = True
            except Exception as exc:
                import traceback
                self.log.write_error([ traceback.format_exc(5) ])
                rollback = True

            # if for some reason the client is still waiting for data to be sent, send it an EOF; also, if the client is somehow
            # still sending data, reject it; however, the client may have already disconnected, in which case calling shutdown()
            # will raise an exception
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass

            if rollback:
                # now we need to figure out the state of the system; a series of API calls were processed and any one of them
                # could have failed; clean-up for the call that failed already happened, but we need to clean-up anything
                # in the pipeline before this call that made changes to SUMS
                for request in reversed(history):
                    request.undo()
                self.dbconn.rollback()
                rollback = False
            else:
                # commit the db changes
                self.dbconn.commit()
        finally:
            # stop the alive server
            if self.aliveServer and self.aliveServer.is_alive():
                self.log.write_debug([ 'stopping alive server for client ' + peerName ])
                self.aliveServer.stop()
                self.aliveServer.join(5.0) # should stop quickly since the worker is not holding the msgLock

            # We need to check the class tList variable to update it, so we need to acquire the lock.
            try:
                Worker.lockTList()
                self.log.write_debug([ 'class Worker acquired Worker lock for client ' + peerName ])
                Worker.tList.remove(self) # This thread is no longer one of the running threads.
                if len(Worker.tList) == Worker.maxThreads - 1:
                    # Fire event so that main thread can add new SUs to the download queue.
                    Worker.eventMaxThreads.set()
                    # Clear event so that main will block the next time it calls wait.
                    Worker.eventMaxThreads.clear()
            except Exception as exc:
                import traceback
                self.log.write_error([ 'there was a problem closing the Worker thread for client ' + speerName ])
                self.log.write_error([ traceback.format_exc(0) ])
            finally:
                Worker.unlockTList()
                self.log.write_debug([ 'class Worker released Worker lock for client ' + peerName ])

                # do not close DB connection, but release it for the next worker
                self.dbconn.release()
                self.log.write_debug([ 'worker released DB connection ' + self.dbconn.getID() + ' for client ' + peerName ])

                # always close the server-side of client-socket pair
                self.log.write_debug([ 'closing the server side of client socket ' + peerName ])
                self.sock.close()

    def getID(self):
        if hasattr(self, 'peerName') and self.peerName and len(self.peerName) > 0:
            return self.peerName
        else:
            # will raise if the socket has been closed by client
            return str(self.sock.getpeername())

    def getRequest(self):
        if hasattr(self, 'request') and self.request:
            return self.request
        else:
            return None

    def extractClientInfo(self, msg):
        # msg is JSON:
        # {
        #    "pid" : 1946,
        #    "user" : "TheDonald"
        # }
        #
        # The pid is a JSON number, which could be a double string. But the client
        # will make sure that the number is a 32-bit integer.
        self.log.write_debug([ self.getID() + ' extracting client info' ])

        clientInfo = Unjsonizer(msg)

        self.clientInfo = DataObj()
        self.clientInfo.data = DataObj()
        if 'pid' not in clientInfo.unjsonized:
            raise ClientInfoException('pid missing from client info')
        self.clientInfo.data.pid = clientInfo.unjsonized['pid']
        if 'user' not in clientInfo.unjsonized:
            raise ClientInfoException('user missing from client info')
        self.clientInfo.data.user = clientInfo.unjsonized['user']

    def extractRequest(self, msg):
        if not self.reqFactory:
            self.reqFactory = RequestFactory(self)

        self.request = self.reqFactory.getRequest(msg)

    def generateResponse(self):
        try:
            self.response = self.request.generateResponse()
        except SDException as exc:
            # Create a response with a non-OK status and an error message.
            raise GenerateResponseException(str(exc))
        except Exception as exc:
            # like on OSError (from the mkdir failing), or a DB error
            import traceback
            raise GenerateResponseException(traceback.format_exc(2))
        return self.response.getJSON()

    def generateErrorResponse(self, status, errMsg):
        self.response = self.request.generateErrorResponse(status, errMsg)
        return self.response.getJSON()

    # msg is a bytes
    def send_msg(self, msg):
        # small timeout when sending (client is waiting for quick response)
        message = Message(msg=msg, sock=self.sock, timeout=20, peer_name=self.getID(), log=self.log)
        message.send()

    # returns a bytes
    def receive_msg(self):
        # big timeout when receiving (client might be processing)
        message = Message(msg=None, sock=self.sock, timeout=self.client_response_timeout * 60, peer_name=self.getID(), log=self.log)
        return message.receive()

    # json_string is a str
    def send_json(self, json_string):
        self.send_msg(bytes(json_string, 'UTF-8'))

    # returns a str
    def receive_json(self):
        msg_bytes = self.receive_msg()
        return msg_bytes.decode('UTF-8') # convert bytes to str

    # Must acquire Worker lock BEFORE calling newThread() since newThread() will append to tList (the Worker threads will be deleted from tList as they complete).
    @staticmethod
    def newThread(sock, has_tape_sys, has_mult_part_sets, timeout, chmown_path, log):
        worker = Worker(sock=sock, has_tape_sys=has_tape_sys, has_mult_part_sets=has_mult_part_sets, timeout=timeout, chmown_path=chmown_path, log=log)
        Worker.tList.append(worker)
        worker.start()

    @staticmethod
    def dumpBytes(msg):
        print(str(["{0:0>2X}".format(b) for b in msg]))

    @classmethod
    def lockTList(cls):
        cls.tListLock.acquire()

    @classmethod
    def unlockTList(cls):
        cls.tListLock.release()

    @classmethod
    def getNumThreads(cls):
        return len(cls.tList)

    @classmethod
    def freeThreadExists(cls):
        return len(cls.tList) < cls.maxThreads

    @classmethod
    def waitForFreeThread(cls):
        cls.eventMaxThreads.wait()

    @classmethod
    def removeThreadFromList(cls, thread):
        cls.tList.remove(thread)

    @classmethod
    def setMaxThreads(cls, maxThreads):
        cls.maxThreads = maxThreads


# one AliverServer per Worker/Session
class AliveServer(threading.Thread):
    workerList = []

    def __init__(self, worker):
        threading.Thread.__init__(self)
        self.worker = worker
        self.halt = False

    def run(self):
        while True:
            # if the worker has the lock, it could block holding it if the client does not read from the socket AND
            # the socket buffer is full
            self.worker.msgLock.acquire()
            try:
                if not self.worker.messageSent:
                    # do not send an alive response if the worker has already sent a response
                    json_string = self.worker.getRequest().generateAliveResponse().getJSON()
                    self.worker.send_json(json_string) # expects a str object; can hang if client does not read AND socket buffer is full
                    self.worker.log.write_debug([ 'sent is-alive to ' + self.worker.getID() ])
            finally:
                self.worker.msgLock.release()

            time.sleep(1.0)
            if self.halt:
                break

    # called by worker
    def stop(self):
        self.halt = True


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


class TestClient(threading.Thread):

    def __init__(self, sock, serverPort, log):
        threading.Thread.__init__(self)
        self.sock = sock
        self.serverPort = serverPort
        self.log = log

    def run(self):
        # First, connect to the server.
        try:
            self.sock.connect((socket.gethostname(), self.serverPort))

            # Send some random SUNUMs to the server thread (one is invalid - 123456789).
            request = {[650547410, 650547419, 650547430, 650551748, 123456789, 650551852, 650551942, 650555939, 650556333]}
            json_string = self.jsonizeRequest(request)
            message = Message(msg=bytes(json_string, 'UTF-8'), sock=self.sock, timeout=20, peer_name=self.getID(), log=self.log)
            message.send()
            message = Message(msg=None, sock=self.sock, timeout=20, peer_name=self.getID(), log=self.log)
            msg_bytes = message.receive()
            json_string = msg_bytes.decode('UTF-8')
            response = self.unjsonizeResponse(json_string) # convert to dict

            self.dumpsInfoList(response)
        except Exception as exc:
            import traceback
            log.write_error([ 'client ' + str(self.sock.getsockname()) + ' had a problem communicating with the server' ])
            log.write_error([ traceback.format_exc(0) ])
        finally:
            self.log.write_debug([ 'closing test client socket' ])
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()

    def jsonizeRequest(self, request):
        return json.dumps(request)

    def unjsonizeResponse(self, msg):
        infoDict = json.loads(msg)
        infoList = infoDict['suinfolist']
        # We now have a list of Info objects.
        return infoList

    def dumpsInfoList(self, infoList):
        for infoDict in infoList:
            self.log.write_debug(['sunum=' + str(infoDict['sunum'])])
            self.log.write_debug(['path=' + infoDict['onlineLoc']])
            self.log.write_debug(['status=' + infoDict['onlineStatus']])
            self.log.write_debug(['archstatus=' + infoDict['archiveStatus']])
            self.log.write_debug(['ack=' + infoDict['offsiteAck']])
            self.log.write_debug(['comment=' + infoDict['historyComment']])
            self.log.write_debug(['series=' + infoDict['owningSeries']])
            self.log.write_debug(['group=' + str(infoDict['storageGroup'])])
            self.log.write_debug(['size=' + str(infoDict['bytes'])])
            self.log.write_debug(['create=' + infoDict['creatDate']])
            self.log.write_debug(['user=' + infoDict['username']])
            self.log.write_debug(['tape=' + infoDict['archTape']])
            self.log.write_debug(['tapefn=' + str(infoDict['archTapeFn'])])
            self.log.write_debug(['tapedate=' + infoDict['archTapeDate']])
            self.log.write_debug(['safetape=' + infoDict['safeTape']])
            self.log.write_debug(['safetapefn=' + str(infoDict['safeTapeFn'])])
            self.log.write_debug(['safetapedate=' + infoDict['safeTapeDate']])
            self.log.write_debug(['pastatus=' + str(infoDict['paStatus'])])
            self.log.write_debug(['pasubstatus=' + str(infoDict['paSubstatus'])])
            self.log.write_debug(['effdate=' + infoDict['effectiveDate']])

def extractAddresses(family):
     addresses = []
     for interface, snics in psutil.net_if_addrs().items():
         for snic in snics:
             if snic.family == family:
                 addresses.append(snic.address)

     return addresses


if __name__ == "__main__":
    rv = RV_SUCCESS
    log = None

    try:
        sumsDrmsParams = SumsDrmsParams()
        if sumsDrmsParams is None:
            raise ParamsException('unable to locate DRMS parameters file (drmsparams.py)')

        parser = CmdlParser(usage='%(prog)s [ -dht ] [ --dbhost=<db host> ] [ --dbport=<db port> ] [ --dbname=<db name> ] [ --dbuser=<db user>] [ --logfile=<log-file name> ]')
        parser.add_argument('-H', '--dbhost', help='The host machine of the database that contains the series table from which records are to be deleted.', metavar='<db host machine>', dest='dbhost', default=sumsDrmsParams.get('SUMS_DB_HOST'))
        parser.add_argument('-P', '--dbport', help='The port on the host machine that is accepting connections for the database that contains the series table from which records are to be deleted.', metavar='<db host port>', dest='dbport', default=sumsDrmsParams.get('SUMPGPORT'))
        parser.add_argument('-N', '--dbname', help='The name of the database that contains the series table from which records are to be deleted.', metavar='<db name>', dest='database', default=sumsDrmsParams.get('DBNAME') + '_sums')
        parser.add_argument('-U', '--dbuser', help='The name of the database user account.', metavar='<db user>', dest='dbuser', default=sumsDrmsParams.get('SUMS_MANAGER'))
        parser.add_argument('-s', '--sockport', help='The server port listening for incoming connection requests.', metavar='<listening socket port>', dest='listenport', type=int, default=int(sumsDrmsParams.get('SUMSD_LISTENPORT')))
        parser.add_argument('-l', '--logfile', help='The file to which logging is written.', metavar='<file name>', dest='logfile', default=os.path.join(sumsDrmsParams.get('SUMLOG_BASEDIR'), SUMSD + '-' + LISTEN_PORT + '-' + datetime.now().strftime('%Y%m%d.%H%M%S') + '.txt'))
        parser.add_argument('-L', '--loglevel', help='Specifies the amount of logging to perform. In order of increasing verbosity: critical, error, warning, info, debug', dest='loglevel', action=LogLevelAction, default=logging.ERROR)
        parser.add_argument('-m', '--maxconn' , help='The maximum number of simultaneous SUMS connections.', metavar='<max connections>', dest='maxconn', default=sumsDrmsParams.get('SUMSD_MAX_THREADS'))
        parser.add_argument('-t', '--test', help='Create a client thread to test the server.', dest='test', action='store_true', default=False)

        arguments = Arguments(parser)

        put_file_path = sumsDrmsParams.get_optional('SUMS_PUT_FILE')
        sums_bin_path = sumsDrmsParams.get_optional('SUMBIN_BASEDIR')
        sum_chmown_path = None

        if sums_bin_path is not None:
            sum_chmown_path = os.path.join(sums_bin_path, 'sum_chmown')

        Worker.setMaxThreads(int(arguments.getArg('maxconn')))
        pid = os.getpid()

        # in the log file name, replace LISTEN_PORT with the actual server socket port over which connections are accepted
        arguments.replArg('logfile', arguments.getArg('logfile').replace(LISTEN_PORT, str(arguments.getArg('listenport'))))

        # Create/Initialize the log file.
        try:
            logFile = arguments.getArg('logfile')
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            log = Log(logFile, arguments.getArg('loglevel'), formatter)
        except exc:
            raise LogException('unable to initialize logging')

        log.write_critical([ 'starting sumsd.py server' ])

        if put_file_path is not None:
            log.write_debug([ '[ __main__ ] initializing updater lock file {lock_file} for put'.format(lock_file=put_file_path) ])
            SUFileOwnerModUpdater.set_lock_file(lock_path=put_file_path, type='put')
        elif sum_chmown_path is not None and os.path.exists(sum_chmown_path):
            lock_path=os.path.join(sumsDrmsParams.get('DRMS_LOCK_DIR'), SUMS_CHMOWN_LOCK_FILE)
            log.write_debug([ '[ __main__ ] initializing updater lock file {lock_file} for chmown'.format(lock_file=lock_path) ])
            SUFileOwnerModUpdater.set_lock_file(lock_path=lock_path, type='chmown')
        else:
            SUFileOwnerModUpdater.set_lock_file(lock_path=None, type=None)
            log.write_warning([ '[ __main__ ] no file owner/priv updater specified' ])

        thContainer = [ arguments, str(pid), log ]
        with TerminationHandler(thContainer) as th:
            try:
                addresses = extractAddresses(socket.AF_INET)

                bound = False
                for address in addresses:
                    # use getaddrinfo() to try as many families/protocols as are supported; it returns a list
                    info = socket.getaddrinfo(address, arguments.getArg('listenport'))

                    for oneAddrInfo in info:
                        family = oneAddrInfo[0]
                        sockType = oneAddrInfo[1]
                        proto = oneAddrInfo[2]

                        try:
                            log.write_info([ 'attempting to create socket with family ' + str(family) + ' and socket type ' + str(sockType) ])
                            serverSock = socket.socket(family, sockType, proto)

                            # by default, serverSock is a blocking socket; set a timeout
                            # value so that the server can monitor all socket read and write
                            # operations for a client that is taking too long (and holding
                            # a Worker potentially indefinitely)
                            serverSock.settimeout(1.0)
                            log.write_info([ 'successfully created socket with family ' + str(family) + ' and socket type ' + str(sockType) ])
                        except OSError:
                            import traceback

                            log.write_warning([ traceback.format_exc(5) ])
                            log.write_warning([ 'trying next address (could not create socket)' ])
                            if serverSock:
                                serverSock.close()
                            continue

                        # now try binding
                        try:
                            serverSock.bind(('', arguments.getArg('listenport')))
                            log.write_info([ 'successfully bound socket to address ' + str(serverSock.getsockname()) + ':' + str(arguments.getArg('listenport')) ])
                            bound = True
                            break # we're good!
                        except OSError:
                            import traceback

                            log.write_warning([ traceback.format_exc(5) ])
                            log.write_warning([ 'trying next address (could not bind address)' ])
                            if serverSock:
                                serverSock.close()
                            continue

                    if bound:
                        break

                # it is possible that we never succeeded in creating and binding the socket
                try:
                    serverSock.listen(128)
                except OSError:
                    log.write_error([ 'could not create socket to listen for client requests' ])
                    raise

                log.write_critical([ 'listening for client requests on ' + str(serverSock.getsockname()) ])
            except Exception as exc:
                if len(exc.args) > 0:
                    raise SocketConnectionException(str(exc.args[0]))
                else:
                    raise SocketConnectionException('failure creating a socket to listen for incoming connections')

            # Something cool. If the test flag is set, then create another thread that sends a SUM_info request to the main thread.
            # At this point, the server is listening, so it is OK to try to connect to it.
            if arguments.getArg('test'):
                clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client = TestClient(clientSocket, arguments.getArg('listenport'), log)
                client.start()

            pollObj = select.poll()
            pollObj.register(serverSock, select.POLLIN | select.POLLPRI)

            # while not sigThread.isShuttingDown():
            try:
                while True:
                    try:
                        fdList = pollObj.poll(500)
                    except IOError as exc:
                        raise PollException('a failure occurred while checking for new client connections')

                    if len(fdList) == 0:
                        # nobody is knocking on the door
                        continue
                    else:
                        (clientSock, address) = serverSock.accept()
                        log.write_critical([ 'accepting a client request from ' + str(clientSock.getpeername()) + ', connected to server ' + str(clientSock.getsockname()) ])

                        while True:
                            Worker.lockTList()
                            try:
                                if Worker.freeThreadExists():
                                    log.write_debug([ 'instantiating a Worker for client ' + str(address) ])
                                    Worker.newThread(clientSock, int(sumsDrmsParams.get('SUMS_TAPE_AVAILABLE')) == 1, int(sumsDrmsParams.get('SUMS_MULTIPLE_PARTNSETS')) == 1, int(sumsDrmsParams.get('SUMS_MT_CLIENT_RESP_TIMEOUT')), sum_chmown_path, log)
                                    break # The finally clause will ensure the Worker lock is released.
                            finally:
                                # ensures the tList lock is released, even if a KeyboardInterrupt occurs while the
                                # lock is being held
                                Worker.unlockTList()

                            # There were no free threads. Wait until there is a free thread.
                            Worker.waitForFreeThread()

                            # We woke up, because a free thread became available. However, that thread could
                            # now be in use. Loop and check again.
            except KeyboardInterrupt:
                # shut down things if the user hits ctrl-c
                pass

            pollObj.unregister(serverSock)

            # kill server socket
            log.write_critical([ 'closing server socket' ])
            serverSock.shutdown(socket.SHUT_RDWR)
            serverSock.close()

            # exit termination handler (raise TerminationHandler.Break to exit without exception propagation)
    except TerminationException as exc:
        msg = str(exc)
        if log:
            log.write_critical([ msg ])
        else:
            print(msg, file=sys.stderr)

        # rv is RV_SUCCESS
    except SDException as exc:
        msg = str(exc)
        if log:
            log.write_error([ msg ])
        else:
            print(msg, file=sys.stderr)

        rv = exc.retcode
    except:
        import traceback
        msg = traceback.format_exc(5)
        if log:
            log.write_error([ msg ])
        else:
            print(msg, file=sys.stderr)
        rv = RV_UNKNOWNERROR

msg = 'exiting with return code ' + str(rv)
if log:
    log.write_critical([ msg ])
else:
    print(msg, file=sys.stderr)

logging.shutdown()

sys.exit(rv)
#
