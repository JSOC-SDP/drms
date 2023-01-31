#!/usr/bin/env python3

from datetime import datetime, timedelta
from enum import Enum
import getpass
import json
import os
from shutil import copyfile
import socket
from sshtunnel import SSHTunnelForwarder
from sys import exit, stdout
import tarfile
import subprocess

from drms_export import Error as ExportError, ErrorCode as ExportErrorCode
from drms_parameters import DRMSParams, DPMissingParameterError
from drms_utils import Arguments as Args, CmdlParser, Formatter as DrmsLogFormatter, Log as DrmsLog, LogLevel as DrmsLogLevel, LogLevelAction as DrmsLogLevelAction, MakeObject, StatusCode as DrmsStatusCode

MANIFEST_FILE = 'jsoc/manifest.txt'

class ErrorCode(ExportErrorCode):
    PARAMETERS = (1, 'failure locating DRMS parameters')
    ARGUMENTS = (2, 'bad arguments')
    MESSAGE_SYNTAX = (3, 'message syntax')
    MESSAGE_TIMEOUT = (4, 'message timeout event')
    UNEXCPECTED_MESSAGE = (5, 'unexpected message')
    TCP_CLIENT = (6, 'TCP socket server creation error')
    CONTROL_CONNECTION = (7, 'control connection')
    DATA_PACKAGE_FILE = (8, 'data package')
    SUBPROCESS = (9, 'subprocess')
    HANDSHAKE = (10, 'handshake')
    DOWNLOAD = (11, 'download')
    LOGGING = (12, 'logging')
    ERROR_MESSAGE = (13, 'error message received')

class DataTransferClientBaseError(ExportError):
    def __init__(self, *, msg=None):
        super().__init__(error_message=msg)

class ParametersError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.PARAMETERS)

class ArgumentsError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.ARGUMENTS)

class MessageSyntaxError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.MESSAGE_SYNTAX)

class MessageTimeoutError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.MESSAGE_TIMEOUT)

class UnexpectedMessageError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.UNEXCPECTED_MESSAGE)

class TcpClientError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.TCP_CLIENT)

class ControlConnectionError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.CONTROL_CONNECTION)

class DataPackageError(DataTransferClientBaseError):
    def __init__(self, *, msg=None, status=None):
        super().__init__(msg=msg)
        self.status = status

    _error_code = ErrorCode(ErrorCode.DATA_PACKAGE_FILE)

class SubprocessError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.SUBPROCESS)

class HandshakeError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.HANDSHAKE)

class DownloadError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.DOWNLOAD)

class LoggingError(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.LOGGING)

class ErrorMessageReceived(DataTransferClientBaseError):
    _error_code = ErrorCode(ErrorCode.ERROR_MESSAGE)

class Arguments(Args):
    _arguments = None

    @classmethod
    def get_arguments(cls, *, program_args, drms_params):
        if cls._arguments is None:
            try:
                server = drms_params.get_required('DX_SERVER')
                server_port = int(drms_params.get_required('DX_LISTEN_PORT'))
                remote_user = getpass.getuser()
            except DPMissingParameterError as exc:
                raise ParametersError(msg=str(exc))

            args = None

            if program_args is not None and len(program_args) > 0:
                args = program_args

            parser = CmdlParser(usage='%(prog)s ')

            # required
            parser.add_argument('product', help='the data product to which the files belong', metavar='<product>', dest='product', required=True)

            # optional
            parser.add_argument('-d', '--download-directory', help='the directory to which tar file will be downloaded', metavar='<download directory>', dest='download_directory', default='.')
            parser.add_argument('-e', '--export-file-format', help='the export file-name format string to be used when creating the exported files', metavar='<export file format>', dest='export_file_format', default=None)
            parser.add_argument('-l', '--logging-level', help='the amount of logging to perform; in order of increasing verbosity: critical, error, warning, info, debug', metavar='<logging level>', dest='logging_level', action=DrmsLogLevelAction, default=DrmsLogLevel.ERROR)
            parser.add_argument('-n', '--number-of-files', help='the number of data files/DRMS_IDs to process at one time', metavar='<number of files>', dest='number_of_files', default=1024)
            parser.add_argument('-t', '--tunneling-off', help='if set, then access handshake server directly', dest='tunneling', action='store_false')
            parser.add_argument('-r', '--remote-user', help='the user on the server that will be authenticated', metavar='<remote user>', dest='remote_user', default=remote_user)
            parser.add_argument('-p', '--private-key-file', help='the local file containing the private SSH key to be used for authentication on the server', metavar='<private key file>', dest='private_key_file', default=None)

            arguments = Arguments(parser=parser, args=args)

            if arguments.tunneling:
                if arguments.remote_user is None or arguments.private_key_file is None:
                    raise ArgumentsError(msg=f'missing remote-user or private-key-file argument')

            # add needed drms parameters
            arguments.server = server
            arguments.server_port = server_port

            cls._arguments = arguments

        return cls._arguments

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
        return getattr(self._data, name)

    def __str__(self):
        return self.message

    @classmethod
    def new_instance(cls, *, json_message, **kwargs):
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
    def receive(cls, *, server_connection, msg_type, log):
        log.write_debug([ f'[ Message.receive ]' ])
        json_message_buffer = []
        open_count = 0
        close_count = 0
        timeout_event = None

        while True:
            try:
                # this is a non-blocking socket; timeout is 1 second
                binary_buffer = server_connection.recv(1024) # blocking
                if timeout_event is None:
                    timeout_event = datetime.now() + timedelta(30)
                if binary_buffer == b'':
                    break
            except socket.timeout as exc:
                # no data written to pipe
                if datetime.now() > timeout_event:
                    raise MessageTimeoutError(msg=f'[ Message.receive ] timeout event waiting for server to send message')
                log.write_debug([ f'[ Message.receive ] waiting for server to send message...' ])
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

        log.write_info([ f'[ Message.receive ] received message from server `{"".join(json_message_buffer)}`' ])

        if len(json_message_buffer) == 0:
            raise MessageSyntaxError(msg=f'[ Message.receive ] empty message (server connection )')

        error_message = None
        try:
            message = cls.new_instance(json_message=''.join(json_message_buffer))
            log.write_debug([ f'[ Message.receive ] got valid message `{str(message)}`' ])
        except UnexpectedMessageError as exc:
            error_message = str(exc)
        except MessageSyntaxError as exc:
            error_message = str(exc)
        except Exception as exc:
            error_message = str(exc)

        if error_message is not None:
            log.write_error([ f'[ Message.receive ] error parsing message `{error_message}`' ])
            message = ErrorMessage(json_message=f'{{ "message" : {MessageType.ERROR.fullname}, "error_message" : {error_message} }}')
        else:
            if not hasattr(message, 'message'):
                log.write_error([ f'[ Message.receive ] message missing `message` attribute' ])
                raise MessageSyntaxError(msg=f'[ Message.receive ] invalid message synax; message must contain `message` attribute')

        if isinstance(message, ErrorMessage):
            raise ErrorMessageReceived(message.values[0])

        if message.message.lower() != msg_type.fullname.lower():
            raise UnexpectedMessageError(msg=f'[ Message.receive ] expecting {msg_type.fullname.lower()} message, but received {message.message.lower()} message')

        log.write_debug([ f'[ Message.receive ] message is of type {str(message)}' ])

        return message.values

    @classmethod
    def send(self, *, server_connection, msg_type, log, **kwargs):
        log.write_debug([ f'[ Message.send ]' ])
        num_bytes_sent_total = 0
        num_bytes_sent = 0
        timeout_event = datetime.now() + timedelta(30.0)

        message_dict = {}
        message_dict['message'] = msg_type.fullname
        message_dict.update(kwargs)
        json_message = json.dumps(message_dict)
        log.write_debug([ f'message: {json_message}' ])
        encoded_message = json_message.encode('utf8')

        # no need to send length of json message since the receiver can simply find the opening and closing curly braces
        while num_bytes_sent_total < len(encoded_message):
            try:
                num_bytes_sent = server_connection.send(encoded_message[num_bytes_sent_total:])
                if not num_bytes_sent:
                    raise SocketError(msg=f'[ Message.send ] socket broken; cannot send message data to server')
                num_bytes_sent_total += num_bytes_sent
            except socket.timeout as exc:
                msg = f'timeout event waiting for server to receive message'
                log.write_debug([ f'[ Message.send ] {msg}' ])

                if datetime.now() > timeout_event:
                    raise MessageTimeoutError(msg=f'{msg}')

        log.write_info([ f'[ Message.send ] sent message `{json_message}` to server `{server_connection.getpeername()}`' ])

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
        self.values = (self.number_of_files)

class DataVerifiedMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.number_of_files)

class RequestCompleteMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = ()

class ErrorMessage(Message):
    def __init__(self, *, json_message=None, **kwargs):
        super().__init__(json_message=json_message, **kwargs)
        self.values = (self.error_message)

def get_arguments(**kwargs):
    args = []
    for key, val in kwargs.items():
        args.append(f'{key} = {val}')

    drms_params = DRMSParams()

    if drms_params is None:
        raise ParametersError(msg=f'unable to locate DRMS parameters file')

    return Arguments.get_arguments(program_args=args, drms_params=drms_params)

def send_verification(control_socket, verification_data, log):
    log.write_debug([ f'[ send_verification ]' ])
    total_bytes_sent = 0
    bytes_sent = 0

    while total_bytes_sent < len(verification_data):
        bytes_sent = control_socket.send(verification_data)
        if bytes_sent == 0:
            raise SocketError(msg=f'control connection to server is broken')

        total_bytes_sent += bytes_sent

def verify_and_store_data(control_socket, downloaded_package_path, log):
    log.write_debug([ f'[ verify_and_store_data ]' ])
    buffer = []
    number_of_files = 0

    # open tar file
    log.write_debug([ f'[ verify_and_store_data ] opening data-package file `{downloaded_package_path}`' ])

    if os.path.exists(downloaded_package_path):
        try:
            with tarfile.open(name=downloaded_package_path, mode='r') as open_archive:
                log.write_debug([ f'[ verify_and_store_data ] extracting manifest file `{MANIFEST_FILE}`' ])
                try:
                    with open_archive.extractfile(MANIFEST_FILE) as manifest_file:
                        # compare the names of the files in the manifest with the names of the files in the archive;
                        #  manifest_entry[0] is (utf8-encoded) drms_id, and  manifest_entry[1] is (utf8-encoded) file name
                        manifest_members = [ (manifest_entry[0].decode(), manifest_entry[1].decode()) for manifest_entry in [ line.split() for line in manifest_file ] ]
                        archive_members = list(filter(lambda member: False if member.find('jsoc') == 0 else True, open_archive.getnames()))

                        if len(manifest_members) != len(archive_members):
                            DataPackageError(msg=f'the package manifest has {len(manifest_members)} entries, but the archive has {len(archive_members)} members', status=PackageVerificationStatus.MISSING_FILE if len(manifest_members) > len(archive_members) else PackageVerificationStatus.UNKNOWN_FILE)

                        # send PACKAGE_VERIFIED
                        log.write_debug([ f'[ verify_and_store_data ] sending {MessageType.PACKAGE_VERIFIED.fullname} message to server' ])
                        Message.send(server_connection=control_socket, msg_type=MessageType.PACKAGE_VERIFIED, **{ 'status' : int(PackageVerificationStatus.VERIFIED), 'number_of_files' : len(archive_members) }, log=log)

                        # send VERIFICATION_READY (even if there are no files being verified)
                        log.write_debug([ f'[ send_verification ] sending {MessageType.VERIFICATION_READY.fullname} message to server' ])
                        Message.send(server_connection=control_socket, msg_type=MessageType.VERIFICATION_READY, number_of_files=len(manifest_members), log=log)

                        # the manifest file is a text file - we do not need to read the whole file into memory to start processing it
                        for drms_id, file in manifest_members:
                            # verify checksum, etc.
                            log.write_debug([ f'[ verify_and_store_data ] verifying data integrity of `{file}`...' ])
                            try:
                                with open_archive.extractfile(file) as data_file:
                                    verification_status = DataFileVerificationStatus.GOOD.fullname # pretend the data are good
                                    log.write_debug([ f'[ verify_and_store_data ] ...DONE' ])

                                    # store file
                                    log.write_debug([ f'[ verify_and_store_data ] storing data file `{file}`...' ])
                                    log.write_debug([ f'[ verify_and_store_data ] ...DONE' ])

                                    # send server verification information
                                    buffer.append(drms_id.encode())
                                    buffer.append(b' ')
                                    buffer.append(verification_status.encode('utf8'))
                                    buffer.append(b'\n')
                                    number_of_files += 1

                                    if number_of_files >= 256:
                                        send_verification(control_socket, b''.join(buffer), log)
                                        buffer = []
                            except KeyError as exc:
                                # data file in manifest, but not in archive; treat as if the file was bad
                                verification_status = 'B'
                                buffer.append(drms_id.encode())
                                buffer.append(b' ')
                                buffer.append(verification_status.encode('utf8'))
                                buffer.append(b'\n')
                                number_of_files += 1

                                log.write_error([ f'[ verify_and_store_data ] missing data file `{file}`' ])
                        if len(buffer) > 0:
                            send_verification(control_socket, b''.join(buffer), log)
                            buffer = []

                        log.write_debug([ f'[ verify_and_store_data ] sent verification data to server' ])
                except KeyError as exc:
                    # missing manifest file
                    raise DataPackageError(msg=f'unable to locate manifest file {MANIFEST_FILE}', status=PackageVerificationStatus.MISSING_MANIFEST)
                except Exception as exc:
                    raise DataPackageError(msg=f'unknown package error `{str(exc)}`', status=PackageVerificationStatus.BAD_PACKAGE)

            # end of data marker
            end_string = b'\\.\n'
            total_num_bytes_sent = 0
            num_bytes_sent = 0

            while total_num_bytes_sent < len(end_string):
                num_bytes_sent = control_socket.send(end_string[num_bytes_sent:])
                total_num_bytes_sent += num_bytes_sent
        except tarfile.ReadError as exc:
            raise DataPackageError(msg=f'invalid tar file `{downloaded_package_path}`', status=PackageVerificationStatus.BAD_PACKAGE)
    else:
        raise DataPackageError(msg=f'unable to open downloaded package {downloaded_package_path}', status=PackageVerificationStatus.CANNOT_FIND_PACKAGE)

    log.write_debug([ f'[ verify_and_store_data ] sent end-of-verification marker to server, sent {str(total_num_bytes_sent)} bytes' ])
    return number_of_files

def download_package(*, private_key_file=None, remote_user, package_host, package_path, downloaded_package_path, log):
    log.write_debug([ f'[ download_package ]' ])

    # emulate a Popen() of some external process; use scp as a placeholder
    command = [ '/usr/bin/scp' ]

    if private_key_file is not None:
        command.append(f'-i {private_key_file}')

    command.extend([ f'{remote_user}@{package_host}:{package_path}', f'{downloaded_package_path}' ])

    log.write_debug([ f'[ download_package ] transferring package: {" ".join(command)}' ])

    try:
        complete_proc = subprocess.run(' '.join(command), shell=True)
    except ValueError as exc:
        # client error - invalid arguments
        raise DownloadError(msg=f'invalid arguments (client error `{str(exc)}`)')
    except OSError:
        # client error - shell cannot be found
        raise DownloadError(msg=f'shell cannot be found (client error `{str(exc)}`)')

    if complete_proc.returncode != 0:
        raise DownloadError(msg=f'download command failed {str(exc)}')

def handshake(*, control_socket, remote_user, private_key_file=None, log, product, number_of_files, export_file_format, download_directory):
    log.write_debug([ f'[ handshake ]' ])

    # connected to server; perform workflow
    client_error = None
    server_error = None
    try:
        number_of_files = 0

        # send CLIENT_READY
        log.write_debug([ f'[ __handshake__ ] sending {MessageType.CLIENT_READY.fullname} message to server' ])
        Message.send(server_connection=control_socket, msg_type=MessageType.CLIENT_READY, **{ 'product' : arguments.product, 'number_of_files' : arguments.number_of_files, 'export_file_format' : arguments.export_file_format }, log=log)

        # receive PACKAGE_READY (or ERROR)
        log.write_debug([ f'[ __handshake__ ] waiting for server to send {MessageType.PACKAGE_READY.fullname} message' ])
        package_verification_status, package_host, package_path = Message.receive(server_connection=control_socket, msg_type=MessageType.PACKAGE_READY, log=log)

        # download package
        # TBD (path of the downloaded package file is `downloaded_package_path`)
        package_dir, package_file = os.path.split(package_path)
        downloaded_package_path = os.path.join(arguments.download_directory, package_file)

        open_archive = None

        if not os.path.exists(arguments.download_directory):
            client_error = DownloadError(msg=f'[ __handshake__ ] download directory `{str(arguments.download_directory)} does not exist`')
            raise client_error

        if private_key_file is not None and not os.path.exists(private_key_file):
            client_error = DownloadError(msg=f'[ __handshake__ ] private-key file `{str(private_key_file)} does not exist`')
            raise client_error

        download_package(private_key_file=private_key_file, remote_user=remote_user, package_host=package_host, package_path=package_path, downloaded_package_path=downloaded_package_path, log=log)

        with tarfile.open(name=downloaded_package_path, mode='r') as open_archive:
            # send verification data
            try:
                number_of_files = verify_and_store_data(control_socket, downloaded_package_path, log)
            except DataPackageError as exc:
                log.write_error([ f'[ __handshake__ ] error verifying package: {str(exc)}' ])
                log.write_debug([ f'[ __handshake__ ] sending {MessageType.PACKAGE_VERIFIED.fullname} message to server' ])
                Message.send(server_connection=control_socket, msg_type=MessageType.PACKAGE_VERIFIED, **{ 'status' : int(exc.status), 'number_of_files' : None }, log=log)

            # send DATA_VERIFIED
            log.write_debug([ f'[ __handshake__ ] sending {MessageType.DATA_VERIFIED.fullname} message to server' ])
            Message.send(server_connection=control_socket, msg_type=MessageType.DATA_VERIFIED, **{ 'status' : int(PackageVerificationStatus.VERIFIED), 'number_of_files' : number_of_files }, log=log)
    except ErrorMessageReceived as exc:
        server_error = exc
        client_error = None
    except ConnectionError as exc:
        client_error = ControlConnectionError(msg=f'[ __handshake__ ] error communicating with server {str(exc)}')
    except DataTransferClientBaseError as exc:
        pass
    except OSError as exc:
        server_error = None
        client_error = DownloadError(msg=f'[ __handshake__ ] error downloading package file from server {str(exc)}')
    except subprocess.SubprocessError as exc:
        server_error = None
        client_error = SubprocessError(msg=f'[ __handshake__ ] {str(exc)}')
    except Exception as exc:
        server_error = None
        client_error = HandshakeError(msg=f'[ __handshake__ ] {str(exc)}')

    if client_error is not None:
        log.write_error([ f'[ __handshake__ ] sending {MessageType.ERROR.fullname} message to server' ])
        Message.send(server_connection=control_socket, msg_type=MessageType.ERROR, **{ 'error_message' : str(client_error) }, log=log)

    # receive REQUEST_COMPLETE (regardless of any previous error received from server)
    log.write_debug([ f'[ __handshake__ ] waiting for server to send {MessageType.REQUEST_COMPLETE.fullname} message' ])
    Message.receive(server_connection=control_socket, msg_type=MessageType.REQUEST_COMPLETE, log=log)

if __name__ == "__main__":
    try:
        arguments = get_arguments()
        try:
            formatter = DrmsLogFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            log = DrmsLog(stdout, arguments.logging_level, formatter)
        except Exception as exc:
            raise LoggingError(msg=f'{str(exc)}')

        log.write_info([ f'[ __main__ ] arguments: {str(arguments)}' ])

        info = socket.getaddrinfo(arguments.server, arguments.server_port)
        log.write_debug([ f'[ __main__ ] network card info for {arguments.server}:{str(arguments.server_port)}:' ])
        log.write_debug([ f'[ __main__ ] {card}' for card in info ])
        control_connected = False
        for address_info in info:
            family = address_info[0]
            sock_type = address_info[1]

            if family == socket.AF_INET and sock_type == socket.SOCK_STREAM:
                socket_address = address_info[4] # 2-tuple for AF_INET family

                if arguments.tunneling:
                    # `remote_bind_address` is address of handshake service, with respect to gateway (solarweb1); since
                    # the handshake server IS the gateway, use 127.0.0.1:6200
                    handshake_address = ('127.0.0.1', socket_address[1])
                    with SSHTunnelForwarder(arguments.server, ssh_username=arguments.remote_user, ssh_pkey=arguments.private_key_file, remote_bind_address=handshake_address) as server:
                        local_binding = server.tunnel_bindings[handshake_address]
                        log.write_debug([ f'[ __main__ ] created SSH tunnel: gateway {arguments.server}, local <> remote bindings {local_binding}:{handshake_address}'])
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control_socket:
                                log.write_info([ f'[ __main__ ] created socket' ])
                                try:
                                    log.write_info([ f'[ __main__ ] connecting to {str(("127.0.0.1", local_binding[1]))}' ])
                                    control_socket.connect(('127.0.0.1', local_binding[1]))
                                    control_connected = True
                                    log.write_info([ f'[ __main__ ] control connection established' ])
                                except OSError as exc:
                                    log.write_info([ f'[ __main__ ] WARNING: connection to {local_binding} failed - {str(exc)}' ])
                                    control_socket.close()
                                    control_socket = None
                                    continue

                                handshake(control_socket=control_socket, remote_user=arguments.remote_user, private_key_file=arguments.private_key_file, log=log, product=arguments.product, number_of_files=arguments.number_of_files, export_file_format=arguments.export_file_format, download_directory=arguments.download_directory)

                                control_socket.shutdown(socket.SHUT_RDWR)
                                log.write_info([ f'[ __main__ ] client shut down CONTROL connection' ])

                            # control socket was closed
                            log.write_info([ f'[ __main__ ] client closed CONTROL connection' ])
                        except OSError as exc:
                            log.write_info([ f'[ __main__ ] {str(exc)}' ])
                            raise TcpClientError(msg=f'failure creating TCP client')
                else:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control_socket:
                            log.write_info([ f'created socket' ])
                            try:
                                log.write_info([ f'[ __main__ ] connecting to {socket_address}' ])
                                control_socket.connect((socket_address[0], socket_address[1]))
                                control_connected = True
                                log.write_info([ f'[ __main__ ] control connection established' ])
                            except OSError as exc:
                                log.write_info([ f'[ __main__ ] WARNING: connection to {socket_address} failed - {str(exc)}' ])
                                control_socket.close()
                                control_socket = None
                                continue

                            handshake(control_socket=control_socket, remote_user=arguments.remote_user, private_key_file=arguments.private_key_file, log=log, product=arguments.product, number_of_files=arguments.number_of_files, export_file_format=arguments.export_file_format, download_directory=arguments.download_directory)

                            control_socket.shutdown(socket.SHUT_RDWR)
                            log.write_info([ f'[ __main__ ] client shut down CONTROL connection' ])


                        # control socket was closed
                        log.write_info([ f'[ __main__ ] client closed CONTROL connection' ])
                    except OSError as exc:
                        log.write_info([ f'[ __main__ ] {str(exc)}' ])
                        raise TcpClientError(msg=f'failure creating TCP client')

            if control_connected:
                break
        if not control_connected:
            raise ControlConnectionError(msg=f'unable to establish CONTROL connection')
    except LoggingError as exc:
        print(str(exc), file=sys.stderr)
    except DataTransferClientBaseError as exc:
        log.write_error([ f'[ __main __ ] client failure `{str(exc)}`' ])

    exit(0)
else:
    # stuff run when this module is loaded into another module; export things needed to call check() and cancel()
    # return json and let the wrapper layer convert that to whatever is needed by the API
    pass
