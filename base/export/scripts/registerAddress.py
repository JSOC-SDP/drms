#!/usr/bin/env python3

from __future__ import print_function
import sys
import os
import fileinput
import email
import re
import smtplib
from datetime import datetime, timedelta
import psycopg2
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../include'))
from drmsparams import DRMSParams

# Return values
RV_ERROR_NONE = 0
RV_ERROR = -1
RV_ERROR_PARAMS = -2
RV_ERROR_DBCMD = -3
RV_ERROR_DBCONNECT = -4
RV_ERROR_TIMEOUT = -5
RV_ERROR_CONFIRMATION = -6
RV_ERROR_MESSAGE = -7
RV_ERROR_ADDRESS = -8
RV_ERROR_BODY = -9
RV_ERROR_MAIL = -10

# By default, procmail prints these lines to the procmail log: 
# From nour4soccer@gmail.com  Fri Feb 10 08:19:23 2017
#  Subject: Re: CONFIRM EXPORT ADDRESS
#   Folder: /home/jsoc/cvs/Development/JSOC/base/export/scripts/register     5390
#
# To disable this default behavior, add the LOGABSTRACT=no variable to .procmailrc.
# Anything printed by this script will appear AFTER these three lines. 

# Print stdin
# import fileinput
# fobj = open('/home/jsoc/thefile2.txt', 'a')
# for line in fileinput.input():
#    print(line, file=fobj)

def getDRMSParam(drmsParams, param):
    rv = drmsParams.get(param)
    if not rv:
        raise Exception('drmsParams', 'DRMS parameter ' + param + ' is not defined.', RV_ERROR_PARAMS)

    return rv

def SendMailSuccess(localName, domainName, confirmation):
    subject = 'EXPORT ADDRESS REGISTERED'
    fromAddr = 'jsoc@solarpost.stanford.edu'
    toAddrs = [ localName + '@' + domainName ]
    msg = 'From: jsoc@solarpost.stanford.edu\nTo: ' + ','.join(toAddrs) + '\nSubject: ' + subject + '\nThis message was automatically generated by the JSOC export system at Stanford.\n\nYour email address has been successfully registered.'

    try:
        server = smtplib.SMTP('solarpost.stanford.edu')
        server.sendmail(fromAddr, toAddrs, msg)
        server.quit()
    except Exception as exc:
        # If any exception happened, then the email message was not received.
        raise Exception('emailBadrecipient', 'Unable to send email message to address to confirm address.', RV_ERROR_MAIL)

def SendMailFailure(localName, domainName, confirmation, msg):
    subject = 'FAILURE REGISTERING EXPORT ADDRESS'
    fromAddr = 'jsoc@solarpost.stanford.edu'
    toAddrs = [ localName + '@' + domainName ]
    msg = 'From: jsoc@solarpost.stanford.edu\nTo: ' + ','.join(toAddrs) + '\nSubject: ' + subject + '\nThis message was automatically generated by the JSOC export system at Stanford.\n\nSorry, we were unable to register your email address. ' + msg

    try:
        server = smtplib.SMTP('solarpost.stanford.edu')
        server.sendmail(fromAddr, toAddrs, msg)
        server.quit()
    except Exception as exc:
        # If any exception happened, then the email message was not received.
        raise Exception('emailBadrecipient', 'Unable to send email message to address to confirm address.', RV_ERROR_MAIL)

if __name__ == "__main__":
    rv = RV_ERROR_NONE
    
    try:
        actualMessage = None
        address = None
        body = None
        localName = None
        domainName = None
        confirmation = None
        
        textIn = sys.stdin.read() # text string (sys.stdin is a str of chars; each char in the text string is a Unicode code point (an integer between 0 and 0x10FFFF))
        
        # Ok, this took 2 hours of my life I will never get back! If there are empty lines, or lines with only whitespace, in the incoming
        # message, then message_from_string() considers every thing after the first empty line the body of the message.
        strippedTextIn = '\n'.join([ line for line in textIn.split('\n') if line.strip() != '' ])
        
        message = email.message_from_string(strippedTextIn) # never fails, even for an invalid email message
        
        if message.is_multipart():
            for amessage in message.get_payload():
                type = amessage.get_content_type()
                disposition = amessage.get_content_disposition()
                
                if type == 'text/plain' and not disposition == 'attachment':
                    actualMessage = amessage
                    break
        else:
            actualMessage = message

        if actualMessage == None:
            raise Exception('raMessage', 'Invalid email message.', RV_ERROR_MESSAGE)

        addressField = actualMessage.get('from')
        
        if not addressField:
            raise Exception('raAddress', "Sender's email address not found in email reply header.", RV_ERROR_ADDRESS)
        
        parsedAddressField = email.utils.parseaddr(addressField)
        if len(parsedAddressField[1]) > 0:
            address = parsedAddressField[1]

        bodyEncoded = actualMessage.get_payload(decode=True)
        if not bodyEncoded:
            raise Exception('raBody', 'Email message has no body.', RV_ERROR_BODY)
            
        body = bodyEncoded.decode('UTF8')
            
        print('** message address: ' + address, file=sys.stderr)
        print('** message body: ' + body, file=sys.stderr)
        
        regExpS = re.compile(r'\[([0-9A-Fa-f]{8}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{4}\-[0-9A-Fa-f]{12})\]')
        matchObj = regExpS.search(body)
        if matchObj:
            confirmation = matchObj.group(1)
            
        if confirmation:
            print('** confirmation: ' + confirmation)

        localName, domainName = address.split('@')

        if confirmation is None:
            raise Exception('raConfirmation', 'Confirmation code not found in email reply from address ' + address + '.', RV_ERROR_CONFIRMATION)

        drmsParams = DRMSParams()
        if drmsParams is None:
            raise Exception('drmsParams', 'Unable to locate DRMS parameters file (drmsparams.py).', RV_ERROR_PARAMS)

        try:
            with psycopg2.connect(database=getDRMSParam(drmsParams, 'DBNAME'), user=getDRMSParam(drmsParams, 'WEB_DBUSER'), host=getDRMSParam(drmsParams, 'SERVER'), port=getDRMSParam(drmsParams, 'DRMSPGPORT')) as conn:
                with conn.cursor() as cursor:
                    cmd = "SELECT A.localname, A.confirmation, A.starttime, D.domainid, D.domainname FROM jsoc.export_addresses AS A, jsoc.export_addressdomains AS D WHERE A.domainid = D.domainid AND A.confirmation = '" + confirmation + "'"
                    try:
                        cursor.execute(cmd)
                        rows = cursor.fetchall()
                        if len(rows) == 0:
                            raise Exception('raConfirmation', 'Confirmation ' + confirmation + ' not recognized from address ' + address + '.', RV_ERROR_CONFIRMATION)
                        if len(rows) != 1:
                            raise Exception('dbCorruption', 'Unexpected number of rows returned: ' + cmd + '.', RV_ERROR_DBCMD)
                    except psycopg2.Error as exc:
                        # Handle database-command errors.
                        raise Exception('dbCmd', exc.diag.message_primary, RV_ERROR_DBCMD)

                    localNameDB = rows[0][0]
                    confirmationDB = rows[0][1]
                    starttimeDB = rows[0][2]
                    domainIDDB = rows[0][3]
                    domainNameDB = rows[0][4]
                    
                    if confirmationDB:
                        try:
                            # Reject if the confirmation code has expired.
                            if datetime.now(starttimeDB.tzinfo) > starttimeDB + timedelta(minutes=int(getDRMSParam(drmsParams, 'REGEMAIL_TIMEOUT'))):
                                SendMailFailure(localName, domainName, confirmation, 'The registration process timed-out. Please visit the export page and register your address again.')
                                raise Exception('raTimeout', 'The confirmation code, ' + confirmation + ', for address ' + localNameDB + '@' + domainNameDB + ' has expired.', RV_ERROR_TIMEOUT)

                            # Remove confirmation code from address's record in jsoc.export_addresses. This is how we signify that the address has
                            # been successfully registered.
                            cmd = 'UPDATE jsoc.export_addresses SET confirmation = NULL WHERE domainid = ' + str(domainIDDB) + " AND localname = '" + localNameDB + "'"

                            try:
                                cursor.execute(cmd)
                            except psycopg2.Error as exc:
                                # Handle database-command errors.
                                raise Exception('dbCmd', exc.diag.message_primary + ": " + cmd, RV_ERROR_DBCMD)

                            SendMailSuccess(localName, domainName, confirmation)
                        except Exception as exc:
                            if len(exc.args) == 3:
                                etype = exc.args[0]
                                msg = exc.args[1]
                                rv = exc.args[2]
                                if etype == 'raTimeout':
                                    # The procmail log captures stderr only.
                                    print(msg, file=sys.stderr)

                                    # Remove row from address table. Don't worry about the domain table. Let the cleanAddresses.py script deal with that.
                                    cmd = 'DELETE FROM jsoc.export_addresses WHERE domainid = ' + str(domainIDDB) + " AND localname = '" + localNameDB + "'"
                                    try:
                                        cursor.execute(cmd)
                                    except psycopg2.Error as exc:
                                        # Handle database-command errors.
                                        raise Exception('dbCmd', exc.diag.message_primary + ": " + cmd, RV_ERROR_DBCMD)
                                else:
                                    raise # Re-raise
                            else:
                                raise # Re-raise
        except psycopg2.DatabaseError as exc:
            # Closes the cursor and connection.
            
            # Man, there is no way to get an error message from any exception object that will provide any information why
            # the connection failed.
            raise Exception('dbConnect', 'Unable to connect to the database.', RV_ERROR_DBCONNECT)

    except Exception as exc:
        if len(exc.args) != 3:
            if localName and domainName and confirmation:
                SendMailFailure(localName, domainName, confirmation, 'Please visit the export page and register your address again.')
            raise # Re-raise
        
        etype = exc.args[0]

        if etype == 'drmsParams' or etype == 'dbCorruption' or etype == 'dbCmd' or etype == 'dbConnect' or etype == 'raConfirmation' or etype == 'emailBadrecipient' or etype == 'raTimeout' or etype == 'raMessage' or etype == 'raAddress' or etype == 'raBody':
            msg = exc.args[1]
            rv = exc.args[2]
            
            if etype == 'raConfirmation':
                SendMailFailure(localName, domainName, confirmation, 'The confirmation code you sent was not recognized. Please visit the export page and register your address again.')
            elif localName and domainName:
                SendMailFailure(localName, domainName, confirmation, msg + '\nPlease visit the export page and register your address again.')

            # The procmail log captures stderr only.
            print(msg, file=sys.stderr)
        else:
            if localName and domainName:
                SendMailFailure(localName, domainName, confirmation, 'Please visit the export page and register your address again.')
            raise # Re-raise

    # It appears that sys.exit() does NOT flush streams.
    sys.stderr.flush()
    sys.exit(rv)
