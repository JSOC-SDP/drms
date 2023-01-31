#!/usr/bin/env python3

import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta
from enum import Enum
from heapq import heapify, heappop, heappush
import uuid
import json
import os
import psutil
import re
import signal
import socket
import socketserver
import sys
import threading

from drms_utils import CmdlParser, Arguments as Args, MakeObject, Formatter as DrmsLogFormatter, Log as DrmsLog, LogLevel as DrmsLogLevel, LogLevelAction as DrmsLogLevelAction, StatusCode as DrmsStatusCode
from drms_parameters import DRMSParams, DPMissingParameterError
from drms_export import Error as ExportError, ErrorCode as ExportErrorCode

class ErrorCode(ExportErrorCode):
    PARAMETERS = (1, 'failure locating DRMS parameters')
    ARGUMENTS = (2, 'bad arguments')
    MESSAGE_SYNTAX = (3, 'message syntax')
    MESSAGE_TIMEOUT = (4, 'message timeout event')
    UNEXCPECTED_MESSAGE = (5, 'unexpected message')
    SOCKET_SERVER = (6, 'TCP socket server creation error')
    CONTROL_CONNECTION = (7, 'control connection')
    SUBPROCESS = (8, 'subprocess')
    EXPORT_FILE = (9, 'export file access')
    LOGGING = (9, 'logging')
    ERROR_MESSAGE = (10, 'error message received')

class DataTransferServerBaseError(ExportError):
    def __init__(self, *, msg=None):
        super().__init__(error_message=msg)

class ParametersError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.PARAMETERS)

class ArgumentsError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.ARGUMENTS)

class MessageSyntaxError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.MESSAGE_SYNTAX)

class MessageTimeoutError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.MESSAGE_TIMEOUT)

class UnexpectedMessageError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.UNEXCPECTED_MESSAGE)

class SocketserverError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.SOCKET_SERVER)

class ControlConnectionError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.CONTROL_CONNECTION)

class SubprocessError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.SUBPROCESS)

class ExportFileError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.EXPORT_FILE)

class LoggingError(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.LOGGING)

class ErrorMessageReceived(DataTransferServerBaseError):
    _error_code = ErrorCode(ErrorCode.ERROR_MESSAGE)

class PackageCreationStatus(DrmsStatusCode):
    CREATED = (0, f'CREATED')
    CANNOT_WRITE_FILE = (1, f'CANNOT_WRITE_FILE')
    BAD_CONTENT = (2, f'BAD_CONTENT')
    ERROR = (3, f'ERROR')

    @property
    def fullname(self):
        return self.description()

class PackageVerificationStatus(DrmsStatusCode):
    VERIFIED = (0, f'VERIFIED')
    CANNOT_FIND_PACKAGE = (1, f'CANNOT_FIND_PACKAGE')
    BAD_PACKAGE = (2, f'BAD_PACKAGE')
    MISSING_MANIFEST = (3, f'MISSING_MANIFEST')
    UNKNOWN_FILE = (4, f'UNKNOWN_FILE')
    MISSING_FILE = (5, f'MISSING_FILE')
    ERROR = (7, f'ERROR')

    @property
    def fullname(self):
        return self.description()

class DataFileVerificationStatus(DrmsStatusCode):
    GOOD = (0, f'G')
    MISSING = (1, f'M') # file was in manifest, but not in package
    VERIFICATION_FAILURE = (2, f'V') # file failed verification test

    @property
    def fullname(self):
        return self.description()

class MessageType(Enum):
    CLIENT_READY = (1, f'CLIENT_READY')
    PACKAGE_READY = (2, f'PACKAGE_READY')
    PACKAGE_VERIFIED = (3, f'PACKAGE_VERIFIED')
    VERIFICATION_READY = (4, f'VERIFICATION_READY')
    DATA_VERIFIED = (5, f'DATA_VERIFIED')
    REQUEST_COMPLETE = (6, f'REQUEST_COMPLETE')
    ERROR = (7, f'ERROR')

    def __new__(cls, value, name):
        member = object.__new__(cls)
        member._value = value
        member.fullname = name

        if not hasattr(cls, '_all_members'):
            cls._all_members = {}
        cls._all_members[name.lower()] = member

        return member

    def __int__(self):
        return self._value

    @classmethod
    def get_member(cls, name):
        if hasattr(cls, '_all_members'):
            return cls._all_members[name.lower()]
        else:
            return None

class Message(object):
    def __init__(self, *, json_message=None, **kwargs):
        if json_message is None:
            self._data = MakeObject(name='data_class', data=kwargs)()
        else:
            self._data = MakeObject(name='data_class', data=json_message)()

    def __getattr__(self, name):
        if hasattr(self._data, name):
            return getattr(self._data, name)
        else:
            return None

    def __str__(self):
        return self.__class__.__name__

    @classmethod
    def new_instance(cls, *, json_message, log, **kwargs):
        log.write_debug([ f'[ Message.new_instance ] ' ])
        msg_type = None
        message = None
        try:
            generic_message = Message(json_message=json_message, **kwargs)
            msg_type = MessageType.get_member(generic_message.message)
            log.write_debug([ f'[ Message.new_instance ] parsing message of type `{generic_message.message}`'])

            if msg_type == MessageType.CLIENT_READY:
                message = ClientReadyMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.PACKAGE_READY:
                message = PackageReadyMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.PACKAGE_VERIFIED:
                message = PackageVerifiedMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.VERIFICATION_READY:
                message = VerificationReadyMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.DATA_VERIFIED:
                message = DataVerifiedMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.REQUEST_COMPLETE:
                message = RequestCompleteMessage(json_message=json_message, **kwargs)
            elif msg_type == MessageType.ERROR:
                message = ErrorMessage(json_message=json_message, **kwargs)

            log.write_debug([ f'[ Message.new_instance ] message values: `{str(message.values)}`' ])
        except Exception as exc:
            raise MessageSyntaxError(msg=f'invalid message string `{json_message}`: `{str(exc)}`')

        if message is None:
            raise UnexpectedMessageError(msg=f'unknown error type `{msg_type.fullname}`')

        return message

    @classmethod
    def receive(cls, *, client_socket, msg_type, initial_buffer=None, log):
        log.write_debug([ f'[ Message.receive ]' ])
        buffer = None
        json_message_buffer = []
        open_count = 0
        close_count = 0
        timeout_event = None

        while True:
            if initial_buffer is not None and len(initial_buffer) > 0 and buffer is None:
                buffer = initial_buffer
            else:
                try:
                    # this is a non-blocking socket; timeout is 1 second
                    binary_buffer = client_socket.recv(1024) # blocking
                    log.write_debug([ f'[ Message.receive ] received data from client `{client_socket.getpeername()}`: {binary_buffer.decode()}' ])
                    if timeout_event is None:
                        timeout_event = datetime.now() + timedelta(30)
                    if binary_buffer == b'':
                        break
                except socket.timeout as exc:
                    # no data written to pipe
                    if datetime.now() > timeout_event:
                        raise MessageTimeoutError(msg=f'[ Message.receive ] timeout event waiting for client {client_socket.getpeername()} to send message')
                        log.write_debug([ f'[ Message.receive ] waiting for client {client_socket.getpeername()} to send message...' ])
                    continue

                buffer = binary_buffer.decode('UTF-8')

            if len(json_message_buffer) == 0:
                # look for opening curly brace
                buffer = buffer.lstrip()
                if buffer[0] == '{':
                    open_count += 1
                else:
                    raise MessageSyntaxError(msg=f'[ Message.receive ] invalid message synax; first character must be {str("{")}')

                json_message_buffer.append(buffer[0])
                buffer = buffer[1:]

            # count opening braces
            open_count += len(buffer.split('{')) - 1

            # count closing braces
            close_count += len(buffer.split('}')) - 1

            json_message_buffer.append(buffer)

            if close_count == open_count:
                break

        log.write_info([ f'[ Message.receive ] received message `{"".join(json_message_buffer)}` from client `{client_socket.getpeername()}`' ])

        error_message = None
        try:
            message = cls.new_instance(json_message=''.join(json_message_buffer), log=log)
            log.write_debug([ f'[ Message.receive ] got valid message `{str(message)}`' ])
        except UnexpectedMessageError as exc:
            error_message = str(exc)
        except MessageSyntaxError as exc:
            error_message = str(exc)
        except Exception as exc:
            error_message = str(exc)

        if error_message is not None:
            log.write_error([ f'[ Message.receive ] error parsing message `{error_message}`' ])
            message = ErrorMessage(json_message=f'{{ "message" : "{MessageType.ERROR.fullname}", "error_message" : "{error_message}" }}')
        else:
            if not hasattr(message, 'message'):
                log.write_error([ f'[ Message.receive ] message missing `message` attribute' ])
                raise MessageSyntaxError(msg=f'[ Message.receive ] invalid message synax; message must contain `message` attribute')

        if isinstance(message, ErrorMessage):
            log.write_error([ f'[ Message.receive ] received error message' ])
            raise ErrorMessageReceived(msg=message.values[0])

        if message.message.lower() != msg_type.fullname.lower():
            raise UnexpectedMessageError(msg=f'[ Message.receive ] expecting {msg_type.fullname.lower()} message, but received {message.message.lower()} message')

        return message.values

    @classmethod
    def send(self, *, client_socket, msg_type, **kwargs):
        log.write_debug([ f'[ Message.send ]' ])
        num_bytes_sent_total = 0
        num_bytes_sent = 0
        timeout_event = datetime.now() + timedelta(30)

        message_dict = {}
        message_dict['message'] = msg_type.fullname
        message_dict.update(kwargs)
        json_message = json.dumps(message_dict)
        encoded_message = json_message.encode('utf8')

        # no need to send length of json message since the receiver can simply find the opening and closing curly braces
        while num_bytes_sent_total < len(encoded_message):
            try:
                num_bytes_sent = client_socket.send(encoded_message[num_bytes_sent_total:])
                log.write_debug([ f'[ Message.send ] sent data to client `{client_socket.getpeername()}`: {encoded_message[num_bytes_sent_total:num_bytes_sent].decode()}' ])
                if not num_bytes_sent:
                    raise ControlConnectionError(msg=f'[ Message.send ] socket broken; cannot send message data to client')
                num_bytes_sent_total += num_bytes_sent
            except socket.timeout as exc:
                msg = f'timeout event waiting for client to receive message'
                if datetime.now() > timeout_event:
                    raise MessageTimeoutError(msg=f'{msg}')
                if self.log:
                    self.log.write_debug([ f'[ Message.send ] {msg}' ])

        log.write_info([ f'[ Message.send ] sent message `{json_message}` to client `{client_socket.getpeername()}`' ])

class ClientReadyMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.product, self.number_of_files, self.export_file_format)

class PackageReadyMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (PackageCreationStatus(self.status), self.package_host, self.package_path)

class PackageVerifiedMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (PackageVerificationStatus(self.status), self.number_of_files)

class VerificationReadyMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.number_of_files, )

class DataVerifiedMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.number_of_files, )

class RequestCompleteMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = ()

class ErrorMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.error_message)

class Arguments(Args):
    _arguments = None

    @classmethod
    def get_arguments(cls, *, program_args, drms_params):
        if cls._arguments is None:
            try:
                server = drms_params.get_required('DX_SERVER')
                listen_port = int(drms_params.get_required('DX_LISTEN_PORT'))
                package_host = drms_params.get_required('DX_PACKAGE_HOST')
                package_root = drms_params.get_required('DX_PACKAGE_ROOT')
                export_bin = drms_params.get_required('BIN_EXPORT')
                export_production_db_user = drms_params.get_required('EXPORT_PRODUCTION_DB_USER')
            except DPMissingParameterError as exc:
                raise ParametersError(msg=str(exc))

            args = None

            if program_args is not None and len(program_args) > 0:
                args = program_args

            parser = CmdlParser(usage='%(prog)s ')

            # required
            parser.add_argument('dbhost', '--dbhost', help='the machine hosting the database that serves DRMS data products', metavar='<db host>', dest='db_host', required=True)

            # optional
            parser.add_argument('-c', '--chunk_size', help='the number of records to process at one time', metavar='<record chunk size>', dest='chunk_size', default=1024)
            parser.add_argument('-H', '--package-host', help='the server hosting the packages', metavar='<package host>', dest='package_host', default=package_host)
            parser.add_argument('-l', '--log-file', help='the path to the log file', metavar='<log file>', dest='log_file', default=None)
            parser.add_argument('-L', '--logging-level', help='the amount of logging to perform; in order of increasing verbosity: critical, error, warning, info, debug', metavar='<logging level>', dest='logging_level', action=DrmsLogLevelAction, default=DrmsLogLevel.ERROR)
            parser.add_argument('-P', '--port', help='the port to listen on for new client connections', metavar='<listening port>', dest='listen_port', default=listen_port)
            parser.add_argument('-R', '--package-root', help='the root path of the packages', metavar='<package root>', dest='package_root', default=package_root)
            parser.add_argument('-S', '--server', help='the server host accepting client connections', metavar='<server>', dest='server', default=server)

            arguments = Arguments(parser=parser, args=args)

            # add needed drms parameters
            arguments.export_bin = '/opt/netdrms-9.51/bin/linux_avx/'
            arguments.export_production_db_user = export_production_db_user

            cls._arguments = arguments

        return cls._arguments

# use socketserver framework to create a multi-threaded TCP server
class DataTransferTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    # self.server_address has 2-tuple of (server ip address, host)

    def __init__(self, address, handler):
        self._all_ports = None
        self._t_lock = threading.Lock() # lock access to server ports to THIS server
        super().__init__(address, handler)

    def get_request(self):
        (control_socket, client_address) = super().get_request()
        self.log.write_info([ f'[ DataTransferTCPServer.get_request ] accepting connection request from client `{str(client_address)}`'])
        return (control_socket, client_address)

class DataTransferTCPRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self._drms_id_regex = None
        super().__init__(request, client_address, server)

    # self.server is the DataTransferTCPServer
    def handle(self):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] '])
        self.server.log.write_info([ f'[ DataTransferTCPRequestHandler.handle ] handling session from client `{str(self.client_address)}`' ])
        terminate = False

        # make the client connection non-blocking, but make a long time out (the data transfer could take minutes, hours) - 6 hours
        self.request.settimeout(21600.0)

        try:
            # receive CLIENT_READY message from client
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] waiting for client `{str(self.client_address)}` to send  {MessageType.CLIENT_READY.fullname} message' ])
            product, number_of_files, export_file_format = Message.receive(client_socket=self.request, msg_type=MessageType.CLIENT_READY, log=self.server.log)

            package_path_tmp = os.path.join(self.server.package_root, f'.{str(uuid.uuid4())}.tar')
            package_path = os.path.join(self.server.package_root, f'{str(uuid.uuid4())}.tar')

            self.server.log.write_info([ f'[ DataTransferTCPRequestHandler.handle ] creating data file {package_path} for client `{str(self.client_address)}`' ])

            # write data to disk, send client path info
            try:
                with open(package_path_tmp, 'w+b') as self._data_file:
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] writing data file for client `{str(self.client_address)}` to file {package_path_tmp}' ])
                    asyncio.run(self.create_package(product=product, number_of_files=number_of_files, export_file_format=export_file_format, package_path=package_path_tmp))
            except SubprocessError as exc:
                # problem creating package content
                raise ExportFileError(msg=f'{str(exc)}', msg_type=MessageType.PACKAGE_READY, kwargs={ 'status' : PackageCreationStatus.BAD_CONTENT })
            except ExportFileError as exc:
                # problem creating package content
                raise ExportFileError(msg=f'{str(exc)}', msg_type=MessageType.PACKAGE_READY, kwargs={ 'status' : PackageCreationStatus.BAD_CONTENT })
            except OSError as exc:
                # unable to open package file for write
                raise ExportFileError(msg=f'{str(exc)}', msg_type=MessageType.PACKAGE_READY, kwargs={ 'status' : PackageCreationStatus.CANNOT_WRITE_FILE })

            # if no failure, rename package
            try:
                os.rename(package_path_tmp, package_path)
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] renamed {package_path_tmp} to {package_path}' ])
            except OSError as exc:
                raise ExportFileError(msg=f'{str(exc)}', status=PackageCreationStatus.CANNOT_WRITE_FILE, msg_type=MessageType.PACKAGE_READY)

            # send PACKAGE_READY message to client; the package COULD be empty (no segments available to export)
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] sending {MessageType.PACKAGE_READY.fullname} message to client `{str(self.client_address)}`' ])
            Message.send(client_socket=self.request, msg_type=MessageType.PACKAGE_READY, status=int(PackageCreationStatus.CREATED), package_host=self.server.package_host, package_path=package_path)

            # receive PACKAGE_VERIFIED
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] waiting for client `{str(self.client_address)}` to send  {MessageType.PACKAGE_VERIFIED.fullname} message' ])
            package_verification_status, number_of_files = Message.receive(client_socket=self.request, msg_type=MessageType.PACKAGE_VERIFIED, log=self.server.log)

            if package_verification_status != PackageVerificationStatus.VERIFIED:
                self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] package error for client `{str(self.client_address)}`: {package_verification_status.fullname}' ])
            else:
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] client `{str(self.client_address)}` verifies that package is valid' ])

                # receive VERIFICATION_READY
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] waiting for client `{str(self.client_address)}` to send {MessageType.VERIFICATION_READY.fullname} message' ])
                Message.receive(client_socket=self.request, msg_type=MessageType.VERIFICATION_READY, log=self.server.log)

                # the export code has completed its run; receive client verification data and update the manifest table - these
                # happen simultaneously and asynchronously
                asyncio.run(self.receive_verification_and_update_manifest(client_socket=self.request, product=product))

                # receive DATA_VERIFIED message from client;
                # client must send a message here (after they have sent the requisite '\.\n'); this allows the client to notify
                # the server of an error
                number_of_files_verified = self._verified_message_values

            # send REQUEST_COMPLETE
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] sending {MessageType.REQUEST_COMPLETE.fullname} message to client `{str(self.client_address)}`' ])
            Message.send(client_socket=self.request, msg_type=MessageType.REQUEST_COMPLETE) # client unblocks on CONTROL connection, then ends CONTROL connection
        except socket.timeout as exc:
            # end session (return from handler)
            terminate = True
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] timeout waiting for client response', f'{str(exc)}'])
        except ControlConnectionError as exc:
            terminate = True
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] failure over CONTROL connection', f'{str(exc)}'])
        except ErrorMessageReceived as exc:
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] received error message from client `{str(self.client_address)}`' ])
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] sending {MessageType.REQUEST_COMPLETE.fullname} message to client `{str(self.client_address)}`' ])
            Message.send(client_socket=self.request, msg_type=MessageType.REQUEST_COMPLETE)
        except DataTransferServerBaseError as exc:
            # send error response; client should shut down socket connection
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] error handling client request: {str(exc)}' ])
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] sending {MessageType.ERROR.fullname} message to client `{str(self.client_address)}`' ])

            if hasatt(exc, 'msg_type') and exc.msg_type is not None:
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] sending {MessageType.PACKAGE_READY.fullname} message to client `{str(self.client_address)}`' ])
                Message.send(client_socket=self.request, msg_type=exc.msg_type, error_message=f'{str(exc)}', **exc.kwargs)
            else:
                Message.send(client_socket=self.request, msg_type=MessageType.ERROR, error_message=f'{str(exc)}')

            Message.send(client_socket=self.request, msg_type=MessageType.REQUEST_COMPLETE)

        try:
            if not terminate:
                # block, waiting for client to terminate connection (to avoid TIME_WAIT)
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.handle ] waiting for client `{str(self.client_address)}` to close CONTROL connection' ])
                if self.request.recv(128) == b'':
                    # client closed socket connection
                    self.server.log.write_info([ f'[ DataTransferTCPRequestHandler.handle ] client `{str(self.client_address)}` closed CONTROL connection' ])
        except socket.timeout as exc:
            # end session (return from handler)
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] timeout waiting for client to terminate control connection', f'{str(exc)}' ])
        except OSError as exc:
            self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.handle ] failure waiting for client to close control connection', f'{str(exc)}' ])
        finally:
            # shut down socket
            try:
                self.request.shutdown(socket.SHUT_RDWR)
                self.request.close()
            except:
                pass

    async def create_package(self, *, product, number_of_files, export_file_format, package_path):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ]' ])
        # get list of DRMS_IDs
        self._fetch_is_done = False
        self._drms_ids = asyncio.Queue()

        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ] fetching {str(number_of_files)} DRMS_IDs for product {product} for client `{str(self.client_address)}`' ])
        await asyncio.gather(self.fetch_drms_ids(product=product, number_of_ids=number_of_files), self.export_package(product=product, export_file_format=export_file_format))
        # export code has completed

    async def receive_verification_and_update_manifest(self, *, client_socket, product):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification_and_update_manifest ]' ])
        # after the last verification-data line, the client sends a single line with the chars '\\.\n'
        self._receive_is_done = False
        self._verified_segments = asyncio.Queue()
        self._verification_data_exist = False
        data_event = asyncio.Event()
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification_and_update_manifest ] receiving verification data for product {product} for client `{str(self.client_address)}`' ])
        await asyncio.gather(self.receive_verification(client_socket=client_socket, data_event=data_event), asyncio.create_task(self.update_manifest(data_event=data_event, product=product)))

    async def fetch_drms_ids(self, *, product, number_of_ids):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.fetch_drms_ids ]' ])
        # this 'fetch' command will create the manifest table should it not exist (but will fail if the series shadow table
        # does not exist); it will populate the manifest table with <segment>='N' rows until there are `number_of_ids` such
        # rows; it uses the series shadow table to populate the manifest table
        #
        # 'fetch' then retrieves `number_of_ids` rows that have at least one <segment>='N' value, returning 'drms_id'
        # rows of the form:
        #   su_arta.hmi__v_avg120:1:power
        #
        # these drms_ids are put into the self._drms_ids queue, which are then consumed by export_package()
        command = [ os.path.join(self.server.export_bin, 'data-xfer-manifest-tables'), f'series={product}', 'operation=fetch', f'n={number_of_ids}',  f'JSOC_DBUSER={self.server.export_production_db_user}', f'JSOC_DBHOST={self.server.db_host}' ]

        try:
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.fetch_drms_ids ] running manifest-table manager for client `{str(self.client_address)}`: {" ".join(command)}' ])
            proc = await asyncio.subprocess.create_subprocess_shell(' '.join(command), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

            while True:
                drms_id = await proc.stdout.readline() # bytes
                if drms_id == b'':
                    break
                await self._drms_ids.put(drms_id.decode().rstrip()) # strings

            await self._drms_ids.join()

            self._fetch_is_done = True

            await proc.wait()
            if proc.returncode is not None:
                # child process terminated
                if proc.returncode == 0:
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.fetch_drms_ids ] manifest manager ran successfully' ])
                    pass
                else:
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.fetch_drms_ids ] manifest manager ran unsuccessfully, returned error code `{str(proc.returncode)}`' ])
                    stdout, stderr = proc.communicate()
                    if stderr is not None and len(stderr) > 0:
                        raise SubprocessError(msg=f'[ fetch_drms_ids ] failure running manifest-table manager: {stderr.decode()}' )
                    else:
                        raise SubprocessError(msg=f'[ fetch_drms_ids ] failure running manifest-table manager' )
            else:
                raise SubprocessError(msg=f'[ fetch_drms_ids ] failure running manifest-table manager; no return code' )
        except (ValueError, OSError) as exc:
            raise SubprocessError(msg=f'[ fetch_drms_ids ] {str(exc)}' )

    async def export_package(self, *, product, export_file_format=None):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.export_package ]' ])
        chunk_of_segments = OrderedDict()
        if self._drms_id_regex is None:
            self._drms_id_regex = re.compile(r'[a-z_][a-z_0-9$]*[.][a-z_][a-z_0-9$]*:([0-9]+):([a-z_][a-z_0-9$]*)')

        # [*] filter ==> provide drms-export-to-stdout manifest series recnums via stdin (used
        # in drms_open_records() - we want to open all records, segments and all, even
        # if we won't be exporting all segments)
        specification = f'{product}_manifest::[*]'
        arg_list = [ 'a=0', 's=0', 'e=1', 'm=1', 'DRMS_DBUTF8CLIENTENCODING=1', f'spec={specification}', f'JSOC_DBUSER={self.server.export_production_db_user}', f'JSOC_DBHOST={self.server.db_host}' ]

        if export_file_format is not None and len(export_file_format) > 0:
            arg_list.append(f'ffmt={export_file_format}')

        try:
            # we need to run drms-export-to-stdout, even if no DRMS_IDs are available for processing; running drms-export-to-stdout will create an empty manifest file in this case
            command = f"{os.path.join(self.server.export_bin, 'drms-export-to-stdout')} {' '.join(arg_list)}"
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ] running export for client `{str(self.client_address)}`: {command}' ])
            proc = await asyncio.subprocess.create_subprocess_exec(os.path.join(self.server.export_bin, 'drms-export-to-stdout'), *arg_list, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

            self.server.log.write_debug([f'[ DataTransferTCPRequestHandler.create_package ] forked child process (pid {str(proc.pid)})'])

            while True:
                # a list of recnum decimal byte strings
                while len(chunk_of_segments) < self.server.chunk_size:
                    try:
                        drms_id = self._drms_ids.get_nowait()
                        # since DRMS_IDs are specific to a segment, a set of DRMS_IDs might contain duplicate recnums; remove dupes with an OrderedDict
                        recnum = self._drms_id_regex.match(drms_id).group(1)
                        segment = self._drms_id_regex.match(drms_id).group(2)
                        segment_id = f'{str(recnum)}:{str(segment)}'
                        chunk_of_segments[segment_id] = 0
                        self._drms_ids.task_done()
                    except asyncio.QueueEmpty:
                        # got all available recnums
                        if self._fetch_is_done:
                            # and there will be no more
                            break

                        # more recnums to come; wait for queue to fill a bit
                        await asyncio.sleep(0.5)

                # we have our chunk of recnums in `chunk_of_segments` (consumed from the self._drms_ids queue)
                if proc.returncode is None:
                    if len(chunk_of_segments) > 0:
                        # send recnums to drms-export-to-stdout (which is expecting recnums from stdin)
                        self.server.log.write_debug([f'[ DataTransferTCPRequestHandler.create_package ] sending {",".join(chunk_of_segments)} to process (pid {str(proc.pid)})'])
                        proc.stdin.write('\n'.join(list(chunk_of_segments)).encode())
                        self.server.log.write_debug([f'[ DataTransferTCPRequestHandler.create_package ] sent chunk of {str(len(chunk_of_segments))} segments to process (pid {str(proc.pid)})'])
                        await proc.stdin.drain()
                else:
                    raise SubprocessError(msg=f'export process died unexpectly, error code {str(proc.returncode)}')

                if self._fetch_is_done:
                    proc.stdin.close()
                    break

            # cannot start reading until all recnums have been sent to export code
            total_num_bytes_read = 0
            total_num_bytes_written = 0
            while True:
                # read data package file from export subprocess
                bytes_read = await proc.stdout.read(16384)
                if bytes_read == b'':
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ] got end of file' ])
                    break

                total_num_bytes_read += len(bytes_read)

                # write binary data chunk to package file
                num_bytes_written = 0
                while num_bytes_written < len(bytes_read):
                    num_bytes_written += self._data_file.write(bytes_read[num_bytes_written:])

                total_num_bytes_written += num_bytes_written

            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ] total num bytes read {total_num_bytes_read}, total num bytes written {total_num_bytes_written}' ])

            await proc.wait()
            self._data_file.flush()
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.create_package ] child process terminated (pid {str(proc.pid)})' ])
        except (ValueError, OSError) as exc:
            raise SubprocessError(msg=f'[ stream_package ] {str(exc)}' )
        except Exception as exc:
            raise ExportFileError(msg=f'{str(exc)}')

    async def receive_verification(self, *, client_socket, data_event):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ]' ])
        data_block = b''
        partial_line_start = None
        partial_line_end = None

        while True:
            try:
                data_block = client_socket.recv(8192)
                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] from client `{str(self.client_address)}` received verification data `{data_block.decode()}`' ])
                if data_block == b'':
                    break

                lines = data_block.decode().split('\n')
                lstripped_lines = [] # leading partial line removed
                full_lines = []
                client_end = False

                if len(lines) >= 3 and len(lines[-1]) == 0 and len(lines[0]) == 0:
                    # data_block starts and ends in newline
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] case 1 {str(lines)}' ])
                    if partial_line_start is not None:
                        # complete previous line
                        full_lines.append(f'{partial_line_start}{lines[0]}')
                        partial_line_start = None

                    # add 'middle' lines
                    full_lines.extend([ line for line in lines[1:-1] if len(line) > 0 ])
                elif len(lines) > 1 and len(lines[-1]) == 0:
                    # data_block ends in newline
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] case 2 {str(lines)}' ])
                    if partial_line_start is not None:
                        # complete previous line
                        full_lines.append(f'{partial_line_start}{lines[0]}')
                        partial_line_start = None

                        # add 'middle' lines
                        full_lines.extend([ line for line in lines[1:-1] if len(line) > 0 ])
                    else:
                        # add 'middle' lines
                        full_lines.extend([ line for line in lines[0:-1] if len(line) > 0 ])
                elif len(lines) > 1 and len(lines[0]) == 0:
                    # data_block starts in newline
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] case 3 {str(lines)}' ])
                    if partial_line_start is not None:
                        # complete previous line
                        full_lines.append(f'{partial_line_start}')
                        partial_line_start = None

                    # add 'middle' lines
                    full_lines.extend([ line for line in lines[1:-1] if len(line) > 0 ])

                    # set partial line start (last line)
                    partial_line_start = lines[-1]
                elif len(lines) == 1:
                    # data_block has no newline
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] case 4 {str(lines)}' ])
                    if partial_line_start is not None:
                        # append to partial line
                        partial_line_start += lines[0]
                    else:
                        partial_line_start = lines[0]
                else:
                    # data_block does not start or end in newline
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] case 5 {str(lines)}' ])
                    if partial_line_start is not None:
                        # complete previous line
                        full_lines.append(f'{partial_line_start}{lines[0]}')
                        partial_line_start = None

                        # add 'middle' lines
                        full_lines.extend([ line for line in lines[1:-1] if len(line) > 0 ])
                    else:
                        full_lines.extend([ line for line in lines[:-1] if len(line) > 0 ])

                    # set partial line start (last line)
                    partial_line_start = lines[-1]

                # if an element is the end-of-verification marker, no more verification data to read - what
                # follows is the DATA_VERIFIED message
                full_line_buffer = []
                message_buffer = []
                for full_line in full_lines:
                    if not client_end:
                        if full_line == '\\.':
                            client_end = True
                            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] received end-of-verification marker from client' ])
                            if partial_line_start is not None:
                                message_buffer.append(partial_line_start)
                                partial_line_start = None
                        else:
                            full_line_buffer.append(full_line)
                    else:
                        message_buffer.append(full_line)

                full_lines = full_line_buffer

                verified_segments = []
                if len(full_lines) > 0:
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] extracting verified recnums from  {str(full_lines)}' ])
                    verified_segments = [ ( self._drms_id_regex.match(line.split()[0]).group(1), self._drms_id_regex.match(line.split()[0]).group(2) ) for line in full_lines if line.split()[1] == DataFileVerificationStatus.GOOD.fullname ]
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] verified segments for client {str(self.client_address)}: {",".join([ recnum + ":" + segment for recnum, segment in verified_segments ])}' ])

                    if len(verified_segments) != len(full_lines):
                        bad_segments = [ ( self._drms_id_regex.match(line.split()[0]).group(1), self._drms_id_regex.match(line.split()[0]).group(2), line.split()[1]) for line in full_lines if line.split()[1] != DataFileVerificationStatus.GOOD.fullname ]

                        self.server.log.write_error([ f'[ DataTransferTCPRequestHandler.receive_verification ] BAD segment: {str(recnum)}:{segment} (code {error_code})' for recnum, segment, error_code in bad_segments ])

                for recnum, segment in verified_segments:
                    # we know we have some verification data
                    if not self._verification_data_exist:
                        self._verification_data_exist = True
                        data_event.set()
                    await self._verified_segments.put((recnum, segment))

                self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] finished sending {len(verified_segments)} recnums for verification processing (for client `{str(self.client_address)}`)' ])

                if client_end:
                    # combine next lines to make the DATA_VERIFIED message; the problem is that
                    # part of the message could already be in the full_lines buffer, and part
                    # could still be in the socket, unread; or all of it could be in the full_lines
                    # buffer, or all of it could be in the socket;
                    # use `Message.receive` with an initialized_buffer to parse properly; returns
                    # a list of messages values (in this case, a list with one element - the number
                    # of files verified)
                    self._verified_message_values = Message.receive(client_socket=client_socket, msg_type=MessageType.DATA_VERIFIED, initial_buffer=''.join(message_buffer), log=self.server.log)
                    self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] verified-message values {str(self._verified_message_values)}' ])

                    break
            except socket.timeout as exc:
                # no data written to pipe
                raise MessageTimeoutError(msg=f'timeout event waiting for server {data_socket.getpeername()} to send data')

        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] finished receiving verification data from client `{str(self.client_address)}`' ])
        await self._verified_segments.join()
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.receive_verification ] finished waiting for verification processing to complete (for client `{str(self.client_address)}`)' ])
        self._receive_is_done = True
        if not self._verification_data_exist:
            data_event.set()

    async def update_manifest(self, *, data_event, product):
        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ]' ])

        await data_event.wait()
        if self._verification_data_exist:
            # only run the manifest-update code if there are verification data
            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ] updating product {product} manifest with data received from client `{str(self.client_address)}`' ])
            try:
                while True:
                    # a list of recnum decimal byte strings
                    chunk_of_segments = {} # str(recnum) -> list of str(segment)
                    while len(chunk_of_segments) < self.server.chunk_size:
                        try:
                            recnum, segment = self._verified_segments.get_nowait()

                            if chunk_of_segments.get(str(recnum)) is None:
                                chunk_of_segments[str(recnum)] = []

                            chunk_of_segments[str(recnum)].append(segment)
                            self._verified_segments.task_done()
                        except asyncio.QueueEmpty:
                            # got all available recnums
                            if self._receive_is_done:
                                # and there will be no more
                                break

                            # more recnums to come; wait for queue to fill a bit
                            await asyncio.sleep(0.5)

                    # we have our chunk of recnums in `chunk_of_segments`
                    if len(chunk_of_segments) > 0:
                        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ] chunk of verified segments sending to manifest-table manager: {str(chunk_of_segments)}' ])
                        # arrange by segments -> recnums, a la:
                        # (segA) -> 5
                        # (segA, segB) -> 1, 8, 3, 22
                        # (segB) -> 2
                        segment_map = {} # segment list -> list of str(recnum)
                        for recnum, segments in chunk_of_segments.items():
                            segment_list = ','.join(segments)
                            if segment_map.get(segment_list) is None:
                                segment_map[segment_list] = []

                            segment_map[segment_list].append(recnum)

                        for segment_list, recnums in segment_map.items():
                            # unlike the subprocess module, the asyncio.subprocess module runs asynchronously
                            arg_list = [ f'series={product}', f'operation=update', f'new_value=Y', f'segments={segment_list}', f'JSOC_DBUSER={self.server.export_production_db_user}', f'JSOC_DBHOST={self.server.db_host}' ]

                            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ] running manifest manager for client `{str(self.client_address)}`: {str(arg_list)}' ])
                            proc = await asyncio.subprocess.create_subprocess_exec(os.path.join(self.server.export_bin, 'data-xfer-manifest-tables'), *arg_list, stdin=asyncio.subprocess.PIPE)

                            proc.stdin.write('\n'.join(recnums).encode())
                            self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ] updated chunk of {len(recnums)} recnums in manifest for client `{str(self.client_address)}`' ])
                            await proc.stdin.drain()
                            proc.stdin.close()
                            await proc.wait()

                    if self._receive_is_done:
                        self.server.log.write_debug([ f'[ DataTransferTCPRequestHandler.update_manifest ] done updating manifest for client `{str(self.client_address)}`' ])
                        break
            except (ValueError, OSError) as exc:
                raise SubprocessError(msg=f'[ fetch_drms_ids ] {str(exc)}' )

def get_arguments(**kwargs):
    args = []
    for key, val in kwargs.items():
        args.append(f'{key} = {val}')

    drms_params = DRMSParams()

    if drms_params is None:
        raise ParametersError(msg=f'unable to locate DRMS parameters file')

    return Arguments.get_arguments(program_args=args, drms_params=drms_params)

def get_addresses(*, family, log):
     addresses = []
     for interface, snics in psutil.net_if_addrs().items():
         for snic in snics:
             if snic.family == family:
                 log.write_info([ f'identified server network address `{snic.address}`' ])
                 addresses.append(snic.address)

     return addresses

if __name__ == "__main__":
    exit_event = threading.Event()

    def quit_server(signo, _frame):
        exit_event.set()

    for sig in ('TERM', 'HUP', 'INT'):
        signal.signal(getattr(signal, f'SIG{sig}'), quit_server);

    try:
        arguments = get_arguments()
        try:
            formatter = DrmsLogFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            if arguments.log_file is None:
                log = DrmsLog(sys.stdout, arguments.logging_level, formatter)
            else:
                log = DrmsLog(arguments.log_file, arguments.logging_level, formatter)
        except Exception as exc:
            raise LoggingError(msg=f'{str(exc)}')

        log.write_info([ f'[ __main__ ] arguments: {str(arguments)}' ])

        # socket addresses available on the hosting machine
        addresses = get_addresses(family=socket.AF_INET, log=log)

        # determine suitable IP address of host
        host_ip = None
        try:
            for info in socket.getaddrinfo(arguments.server, arguments.listen_port):
                # limit to streaming internet connections
                if info[0] != socket.AF_INET:
                    continue
                if info[1] != socket.SOCK_STREAM:
                    continue

                host_ip = info[4][0]
        except OSError as exc:
            raise SocketserverError(msg=f'failure checking suitability of server: {str(exc)}')

        if host_ip is None:
            # host running the TCP server is not suitable
            raise SocketserverError(msg=f'host {arguments.server} is not a suitable for running the TCP server')

        bound = False
        for address in addresses:
            try:
                # use getaddrinfo() to try as many families/protocols as are supported; it returns a list
                info = socket.getaddrinfo(address, arguments.listen_port)
            except OSError as exc:
                raise SocketserverError(msg=f'failure checking suitability of server: {str(exc)}')

            for address_info in info:
                family = address_info[0]
                socket_address = address_info[4] # 2-tuple for AF_INET family

                if socket_address[0] != host_ip:
                    continue

                try:
                    log.write_info([ f'[ __main__ ] attempting to create {str(family)} TCP server with address`{str(socket_address)}`' ])

                    with DataTransferTCPServer(socket_address, DataTransferTCPRequestHandler) as data_server:
                        bound = True
                        # can re-use socket_address after socket is closed
                        log.write_info([ f'[ __main__ ] successfully created socketserver server, listening on {str(socket_address)}' ])

                        data_server.chunk_size = arguments.chunk_size
                        data_server.export_bin = arguments.export_bin
                        data_server.package_host = arguments.package_host
                        data_server.package_root = arguments.package_root
                        data_server.export_production_db_user = arguments.export_production_db_user
                        data_server.db_host = arguments.db_host
                        data_server.log = log

                        data_server_thread = threading.Thread(target=data_server.serve_forever)
                        data_server_thread.daemon = True
                        data_server_thread.start()
                        log.write_info([ f'[ __main__ ] successfully started server thread' ])

                        exit_event.wait()
                        log.write_info([ f'[ __main__ ] received shutdown signal...shutting down TCP server' ])
                        data_server.shutdown()

                    log.write_info([ f'[ __main__ ] successfully shut down TCP server' ])
                    break
                except OSError as exc:
                    log.write_warning([ f'[ __main__ ] {str(exc)}' ])
                    log.write_warning([ f'[ __main__ ] trying next address (could not create socketserver on {str(arguments.listen_port)})' ])
                    continue

            if bound:
                break
        if not bound:
            raise SocketserverError(msg=f'failure creating TCP server')
    except DataTransferServerBaseError as exc:
        log.write_error([ str(exc) ])

    sys.exit(0)
else:
    # stuff run when this module is loaded into another module; export things needed to call check() and cancel()
    # return json and let the wrapper layer convert that to whatever is needed by the API
    pass
