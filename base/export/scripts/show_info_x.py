#!/usr/bin/env python

from __future__ import print_function
import sys
import os
import cgi
import json
from subprocess import check_call, CalledProcessError, PIPE
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../include'))
from drmsparams import DRMSParams

MOD_BIN = '/home/jsoc/cvs/Development/JSOC/bin/linux_x86_64'

err = None
msg = None

try:
    optD = {}
    allArgs = []

    arguments = cgi.FieldStorage()

    if arguments:
        for key in arguments.keys():
            val = arguments.getvalue(key)
            
            if key in ('s', 'series'):
                # If the caller provides the series argument twice, then val will be a list, not a string. Raise an exception if that
                # happens (a list has no split method).
                if type(val) is list:
                    raise Exception('invalidArgs', 'The series argument appears more than once in the argument list.')
                optD['series'] = val.split(',')
            else:
                # Save all arguments so we can pass them onto the jsoc_info binary.
                allArgs.append(key + '=' + val)

    # Enforce requirements. Although show_info can be called with SUNUMs instead of a record-set specification, from lookdata.html
    # the ds parameter will always be provided.
    if not 'series' in optD:
        raise Exception('invalidArgs', 'Missing required argument ' + "'series'.")

    drmsParams = DRMSParams()

    if drmsParams is None:
        raise Exception('drmsParams', 'Unable to locate DRMS parameters file (drmsparams.py).')

    # Ensure that series is in whitelist.
    wl = {}
    wlfile = drmsParams.get('WL_FILE')

    with open(wlfile, 'r') as fin:
        for line in fin:
            wl[line.rstrip('\n').lower()] = True

    for aseries in optD['series']:
        if aseries.lower() not in wl:
            raise Exception('noPrivs', "Access to the internal DRMS data series '" + aseries + "' denied.")

    # The remaining arguments (e.g., op, ds) will be passed via the env var QUERY_STRING (for GET HTTP) or STDIN (for POST HTTP).
    cmdList = [MOD_BIN + '/show_info', 'JSOC_DBHOST=' + drmsParams.get('SERVER'), 'DRMS_DBTIMEOUT=600000', 'DRMS_QUERY_MEM=2048']
    cmdList.extend(allArgs)

    check_call(cmdList)

except ValueError as exc:
    err = 'invalidArgs'
    msg = exc.strerror
except KeyError as exc:
    # A DRMSParams exception.
    err = 'undefinedParam'
    msg = 'Undefined DRMS parameter.' + exc.strerror
except CalledProcessError as exc:
    err = 'jsocinfoCall'
    msg = exc.strerror
except Exception as exc:
    if len(exc.args) != 2:
        err = 'unhandledExc'
        msg = 'Unhandled exception.'
    else:
        if exc.args[0] == 'drmsParams':
            err = 'drmsParams'
        elif exc.args[0] == 'invalidArgs':
            err = 'invalidArgs'
        elif exc.args[0] == 'noPrivs':
            err = 'permDenied'
        else:
            err = 'unknownErr'

        msg = exc.args[1]

if err:
    print('Content-type: application/json\n')
    rootObj = {}
    rootObj['err'] = err
    rootObj['errMsg'] = msg
    print(json.dumps(rootObj))

sys.exit(0)
