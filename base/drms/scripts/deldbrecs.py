#!/home/jsoc/bin/linux_x86_64/activepython

import sys
import os.path
import getopt
import pwd
import re
import psycopg2

# Return codes
RET_SUCCESS = 0
RET_INVALIDARG = 1
RET_DBCONNECT = 2
RET_SQL = 3

# Read arguments
# (s)eriestable - The series table from which we are deleting records.
# (r)ecnums     - The list of recnums that specify the db records to delete from seriestable.
#                 The format maybe a single recnum, a list of comma-separated recnums, or a file
#                 containing a list of newline-separated recnums.
# db(n)ame      - The name of the database that contains the series table from which we are deleting
#                 records.
# db(h)ost      - The host machine of the database that contains the series table from which we
#                 are deleting records.
# db(p)ort      - The port on the host machine that is accepting connections for the database that
#                 contains the series table from which we are deleting records.
# (d)oit        - If set, then the script will execute the SQL with the delete statement in it.
#                 Otherwise, the script will merely print out the SQL commands it would otherwise
#                 execute.

def GetArgs(args):
    istat = bool(0)
    optD = {}
    
    try:
        opts, remainder = getopt.getopt(args, "hs:r:n:h:p:d", ["stable=", "recnums=", "dbname=", "dbhost=", "dbport="])
    except getopt.GetoptError:
        print('Usage:\n  deldbrecs.py [-h] -s <series> -r <recnum list> -n <db name> -h <db host> -p <db port> [-d]', file=sys.stderr)
        istat = bool(1)

    if istat == bool(0):
        for opt, arg in opts:
            if opt == '-h':
                print('Usage:\n  deldbrecs.py [-h] -s <series> -r <recnum list> -n <db name> -h <db host> -p <db port> [-d]')
                sys.exit(0)
            elif opt in ("-s", "--stable"):
                regexp = re.compile(r"\s*(\S+)\.(\S+)\s*")
                matchobj = regexp.match(arg)
                if matchobj is None:
                    istat = bool(1)
                else:
                    optD['ns'] = matchobj.group(1)
                    optD['table'] = matchobj.group(2)
            elif opt in ("-r", "--recnums"):
                # Is the argument a file?
                if os.path.isfile(arg):
                    # If the argument is a file, parse it.
                    optD['recnums'] = list()
                    
                    try:
                        with open(arg, 'r') as fin:
                            while True:
                                recnumsRaw = fin.readlines(8192)
                                if not recnumsRaw:
                                    break
                                recnums = [recnum.strip(' \t\n,') for recnum in recnumsRaw]
                                optD['recnums'].extend(recnums)
                    except IOError as exc:
                        type, value, traceback = sys.exc_info()
                        print(exc.strerror, file=sys.stderr)
                        print('Unable to open ' + "'" + value.filename + "'.", file=sys.stderr)
                        istat = bool(1)
                else:
                    # Otherwise, parse the argument itself.
                    optD['recnums'] = arg.split(',') # a list
            elif opt in ("-n", "--dbname"):
                optD['dbname'] = arg
            elif opt in ("-h", "--dbhost"):
                optD['dbhost'] = arg
            elif opt in ("-p", "--dbport"):
                optD['dbport'] = arg
            elif opt == '-d':
                # DoIt!
                optD['doit'] = 1
            else:
                optD[opt] = arg

    if istat or not optD or not 'ns' in optD or not 'table' in optD or not 'recnums' in optD or not 'dbname' in optD or not 'dbhost' in optD or not 'dbport' in optD:
        print(optD)
        print('Missing required arguments.', file=sys.stderr)
        optD = list()
    return optD

rv = RET_SUCCESS

# Parse arguments
if __name__ == "__main__":
    optD = GetArgs(sys.argv[1:])
    if not optD:
        rv = RET_INVALIDARG
    else:
        series = optD['ns'] + '.' + optD['table']
        recnums = optD['recnums']
        dbuser = pwd.getpwuid(os.getuid())[0]
        dbname = optD['dbname']
        dbhost = optD['dbhost']
        dbport = optD['dbport']
        if 'doit' in optD:
            doit = 1
        else:
            doit = 0

if rv == RET_SUCCESS:
    # Connect to the database
    try:
        # The connection is NOT in autocommit mode. If changes need to be saved, then conn.commit() must be called.
        with psycopg2.connect(database=dbname, user=dbuser, host=dbhost, port=dbport) as conn:
            with conn.cursor() as cursor:
                if doit:
                    cursor.execute('PREPARE preparedstatement AS DELETE FROM ' + series + ' WHERE recnum in ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)')
                else:
                    print('PREPARE preparedstatement AS DELETE FROM ' + series + ' WHERE recnum in ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)')
                reclist = list()
                
                for recnum in recnums:
                    reclist.append(recnum)
                    if len(reclist) == 16:
                        if doit:
                            cursor.execute('EXECUTE preparedstatement (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', reclist)
                        else:
                            print('EXECUTE preparedstatement (' + ','.join(reclist) + ')')
                        reclist = list()

                if len(reclist) > 0:
                    # Unprocessed recnums (because len(recnums) was not a multiple of 16).
                    # Pad reclist with recnum = -1
                    for irec in range(16 - len(reclist)):
                        reclist.append('-1')
                    
                    if doit:
                        cursor.execute('EXECUTE preparedstatement (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', reclist)
                    else:
                        print('EXECUTE preparedstatement (' + ','.join(reclist) + ')')
                    reclist = list()

    except psycopg2.Error as exc:
        # Closes the cursor and connection
        print(exc.diag.message_primary, file=sys.stderr)
        # No need to close cursor - leaving the with block does that.
        if not conn:
            rv = RET_DBCONNECT
        else:
            rv = RET_SQL

    # There is no need to call conn.commit() since connect() was called from within a with block. If an exception was not raised in the with block,
    # then a conn.commit() was implicitly called. If an exception was raised, then conn.rollback() was implicitly called.

sys.exit(rv)
