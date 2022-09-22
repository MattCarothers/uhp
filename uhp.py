#!/usr/bin/env python3

# usage: uhp.py [-h] [-H HOST] [-f FILE] [-a AUTO_MACHINE_DIR]
#                      [-m MAX_BYTES] [-v] [-q] [-r] [-j] [-s]
#                      config_file [port [port ...]]
# 
# positional arguments:
#   config_file           Config file
#   port                  bind port
# 
# optional arguments:
#   -h, --help            show this help message and exit
#   -H HOST, --host HOST  bind host (defaults to 0.0.0.0)
#   -f FILE, --file FILE  log file (JSON)
#   -a AUTO_MACHINE_DIR, --auto-machine-dir AUTO_MACHINE_DIR
#                         directory to write auto machine configs
#   -m MAX_BYTES, --max-bytes MAX_BYTES
#                         maximum bytes to log per session
#   -v, --verbose         output debugging information
#   -q, --quiet           suppress stdout log output
#   -r, --log-replies     log what we return to clients
#   -j, --json            log JSON to stdout
#   -s, --log-sessions    log sessions as single events rather than one event
#                         per line

import argparse
import configparser
import copy
import hashlib
import hpfeeds
import io
import logging
import logging.handlers
import json
import os
import re
import socket
import socketserver
import ssl
import sys
import threading
import time
import yaml
from datetime import datetime
from uuid import uuid4

logger = logging.getLogger('uhp')

class UHPEvent():
    def __init__(self, src_ip, src_port, dest_ip, dest_port, action, message, tags=[], fields={}, session_id=None, signature=None):
        # Network info
        self.src_ip     = src_ip
        self.src_port   = src_port
        self.dest_ip    = dest_ip
        self.dest_port  = dest_port
        # Session ID for the machine
        self.session_id = session_id
        # Event action (connect, disconnect, send, recv, noop)
        self.action  = action
        # Text we sent or received
        self.message = message
        # Tags set by a machine or a rule
        self.tags    = tags
        # ConfigGenerator signature
        if signature:
            self.signature = signature
        # Additional fields added by a machine or rule
        for key, value in fields.items():
            setattr(self, key, value)

    def __repr__(self):
        return("{src_ip}:{src_port} -> {dest_ip}:{dest_port} {action:<10} {tags} {message}".format(**self.__dict__))

class UniversalHoneyPot():
    def __init__(self, config):
        """
        @summary: Construct a UniversalHoneyPot
        @param: config: {dict} Configuration for the state machine, including
                the initial banner, state transition rules, and text to return
                to the client.
        """
        # All machines start in _START
        self.state  = "_START"
        self.config = config
        self.states = config['states']
        # Do we have any global tags?
        if "tags" in config:
            self.tags = config['tags']
        else:
            self.tags = []

        # Do we have any custom fields?
        if "fields" in config:
            self.fields = config['fields']
        else:
            self.fields = {}

        # Create a default empty shared state
        if "_SHARED" not in self.states:
            self.states['_SHARED'] = []

        if "banner" in config:
            self.banner = config['banner']
        else:
            self.banner = None

        # Set a unique ID for this session so we can track related logs
        self.session_id = str(uuid4())

        # Signatures are md5 hashes of input text created by a ConfigGenerator
        self.signature = None

    def run(self, input_):
        """
        @summary: Change states based on input.  Return the output associated
                  with the state change.
        """
        # Iterate through the transition rules for this state
        for rule in self.states[self.state] + self.states['_SHARED']:
            # Does the pattern match?
            if "match_case" in rule and rule['match_case']:
                m = re.search(rule['pattern'], input_)
            else:
                m = re.search(rule['pattern'], input_, re.IGNORECASE)
            if m:
                # The pattern matches, so transition to our next state if one
                # was provided.  A rule without a "next" stays in the same
                # state but still returns output.
                if "next" in rule:
                    logger.debug("'{}' matched /{}/ | {} -> {}".format(
                        input_, rule['pattern'], self.state, rule['next'])
                    )
                    self.state = rule['next']
                else:
                    logger.debug("'{}' matched /{}/ | {} -> {}".format(
                        input_, rule['pattern'], self.state, self.state)
                    )
                # Add a {date} key for output
                dt = datetime.utcnow()
                output_fields = {}
                if "datefmt" in rule:
                    date = dt.strftime(rule['datefmt'])
                elif "datefmt" in self.config:
                    date = dt.strftime(self.config['datefmt'])
                else:
                    date = str(dt)
                output_fields['date'] = date

                # Add regex matches.  These can be accessed in the rule output
                # as {match[0]} ... {match[N]}
                output_fields['match'] = m.groups()

                # The output might be a format string expecting matches
                # from the regex.
                try:
                    # Catch this exception in case the format string has more
                    # replacement fields than there were matches.
                    # Include m.groupdict() as well for named parameters. E.g.
                    #     "pattern" : "^USER (?P<username>.*),
                    #     "output"  : "Hello, {username}"
                    output = rule['output'].format(**output_fields, **m.groupdict())
                except:
                    if "output" in rule:
                        output = rule['output']
                    elif "live_file" in rule:
                        output = open(rule['live_file'], 'rb')
                    else:
                        output = ""

                # Do we have tags to apply?
                tags = self.tags
                if "tags" in rule:
                    tags = tags + rule['tags']

                # Do we need to add additional fields?
                if "fields" in rule:
                    for key, value in rule['fields'].items():
                        # Add the fields to our machine so they persist
                        # between states
                        self.fields[key] = value.format(**output_fields)

                return(output, tags, self.fields)
            else:
                logger.debug("'{}' did not match /{}/ | {} -> {}".format(
                    input_, rule['pattern'], self.state, self.state))
        # No rules matched
        logger.debug("'{}' did not match any patterns | {} -> {}".format(
            input_, self.state, self.state))
        return(None, self.tags, self.fields)

    @staticmethod
    def validate(config):
        # Validate our config
        if "states" not in config:
            raise RuntimeError("No states defined in config")
        states = config['states']
        if not isinstance(states, dict):
            raise RuntimeError("'states' should be a hash")
        if "_START" not in states:
            raise RuntimeError("No _START state defined in config")
        for state in states:
            for rule in states[state]:
                if "tags" in rule and not isinstance(rule['tags'], list):
                    raise RuntimeError("Tags should be an array of strings")
                if "next" in rule and rule['next'] != "_END" and rule['next'] not in states:
                    raise RuntimeError("Rule next value '%s' points to a non-existent state" % (rule['next']))
                if "file" in rule:
                    with open(rule['file'], 'r') as f:
                        rule['output'] = rule.get('output', '') + f.read()

class ConfigGenerator():
    """
    ConfigGenerator is an object that dynamically constructs a UniversalHoneyPot
    configuration file based on client input.
    """
    def __init__(self, server):
        self.state     = 0
        self.hash      = hashlib.md5()
        self.config    = { 'states' : { } }
        self.directory = server.server.auto_machine_dir
        self.yaml      = server.server.yaml
        self.src_ip    = server.src_ip
        self.src_port  = server.src_port
        self.dest_ip   = server.dest_ip
        self.dest_port = server.dest_port
    
    def advance(self, pattern):
        # If we're in state 0, use "_START_ instead
        current_state = self.state or "_START"
        self.config['states'][str(current_state)] = [
            { 'pattern' : pattern, 'next' : str(self.state + 1) }
        ]
        self.state = self.state + 1
        self.hash.update(bytes(pattern, 'utf8'))

    def write(self):
    # If we didn't get any input, there's nothing to do
        if not self.state:
            return
        # Create a filename based on source ip, dest port, and the
        # hash of the input
        filename = '-'.join([
            self.src_ip, str(self.dest_port), self.hash.hexdigest()
        ])
        # Rewrite the last state's next to _END
        if self.state == 1:
            self.config['states']['_START'][0]['next'] = "_END"
        else:
            self.config['states'][str(self.state - 1)][0]['next'] = "_END"
        with open(self.directory + '/' + filename, 'w') as f:
            if self.yaml:
                f.write(yaml.dump(self.config, default_flow_style=False, explicit_start=True))
                f.write("\n")
            else:
                f.write(json.dumps(self.config, sort_keys=True, indent=4))
                f.write("\n")
            logger.debug("Wrote " + self.directory + '/' + filename)

###################
# Server routines #
###################

class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
    def write_to_client(self, string_or_filehandle, tags=[], fields={}):
        """
        @summary: write a string or the contents of a file handle back to the
                  client use tarpitting to slow the output down if using -T
        """
        log_entry = string_or_filehandle
        if isinstance(string_or_filehandle, io.BufferedReader):
            fh = string_or_filehandle
            log_entry = "contents of " + fh.name
        else:
            fh = io.BytesIO(bytes(string_or_filehandle, 'utf8'))

        data = fh.read(self.server.tarpit_bytes)
        try:
            while data:
                self.wfile.write(data)
                data = fh.read(self.server.tarpit_bytes)
                time.sleep(self.server.tarpit_seconds)
        # Bail out gracefully if the client disconnects
        except BrokenPipeError:
            pass

        fh.close()

        if self.server.log_replies:
            if log_entry:
                self.log("send", log_entry.rstrip(), tags, fields)
            else:
                self.log("noop", output, tags, fields)


    def handle(self):
        """
        @summary: Handle a TCP connection.  Read from the client until
                  it disconnects or our state machine reaches _END state.
        """
        # Store connection information here because later calls to
        # getpeername() and getsockname() can raise an OSError
        try:
            self.src_ip,  self.src_port  = self.connection.getpeername()
            self.dest_ip, self.dest_port = self.connection.getsockname()
        except:
            return
        # Track how long each session lasts
        self.start_time = time.time()

        # Intialize two variables to hold all the text send and received.
        # We'll used this if server.config.log_sessions is true and we're
        # logging entire sessions instead of individual lines.
        self.session_send = ""
        self.session_recv = ""
        # Initialize the state machine
        self.machine = UniversalHoneyPot(self.server.config)
        self.log("connect")

        # Initialize the auto machine generator if needed
        if self.server.auto_machine_dir:
            config_generator = ConfigGenerator(self)

        # Write out the banner if there is one
        if self.machine.banner:
            # Set up the date so we can output it in the banner if needed
            dt = datetime.utcnow()
            if "datefmt" in self.server.config:
                date = dt.strftime(self.server.config['datefmt'])
            else:
                date = str(dt)
            banner = self.machine.banner.format(**{ 'date' : date })
            self.write_to_client(banner, self.machine.tags, self.machine.fields)

        # Keep track of bytes received so we can truncate if -m is set
        bytes_remaining = self.server.max_bytes

        # Loop as long as there's input
        try:
            for line in self.rfile:
                if not line:
                    break
                try:
                    line = line.decode('utf8')
                except:
                    continue

                # Check to see if we've exceeded max bytes, and truncate if so
                if server.max_bytes:
                    if len(line) > bytes_remaining:
                        line = line[0:bytes_remaining]
                        self.machine.truncated = True
                    # Subtract this line's bytes from the amount remaining. If
                    # it's <= 0, we'll terminate the session after running the
                    # machine.
                    bytes_remaining = bytes_remaining - len(line)
                
                # Run the machine on the input, and return the output to the
                # client
                output, tags, fields = self.machine.run(line.rstrip())
                self.log("recv", line, tags, fields)
                # Did the machine produce output to send back to the client?
                # Is it a file handle?
                self.write_to_client(output, tags, fields)

                # Advance the config generator if needed
                if self.server.auto_machine_dir and "am_ignore" not in tags:
                    config_generator.advance(line.rstrip())

                # End the session if max_bytes is set and we've exceeded the
                # limit
                if self.server.max_bytes and bytes_remaining <= 0:
                    break

                # Machine state _END means we're done
                if self.machine.state == "_END":
                    break
        except Exception as e:
            print(repr(e))
            pass

        # Clean up by logging the disconnect and writing out our new auto config
        if self.server.auto_machine_dir:
            config_generator.write()
            self.machine.signature = config_generator.hash.hexdigest()
        duration = time.time() - self.start_time
        self.log("disconnect", "session lasted %0.2f seconds" % duration)

    def log(self, action, message="", tags=[], fields={}, session_id=None):
        """
        @summary: log output
        """
        tags       = tags or self.machine.tags
        fields     = fields or self.machine.fields
        session_id = session_id or self.machine.session_id
        # Are we configured to log entire sessions in one event?
        # If so, store sends and receives for later, and emit a
        # log on disconnect.
        if self.server.log_sessions:
            if action == "send":
                self.session_send = self.session_send + message
            elif action == "recv":
                self.session_recv = self.session_recv + message
            elif action == "disconnect":
                fields['duration'] = time.time() - self.start_time
                event = UHPEvent(
                    self.src_ip, self.src_port,
                    self.dest_ip, self.dest_port,
                    "recv", self.session_recv, tags,
                    fields, session_id, self.machine.signature
                )
                logger.warning(event)
                # Send a second event for the transmitted data if configured
                # to do so.
                if self.server.log_replies:
                    event = UHPEvent(
                        self.src_ip, self.src_port,
                        self.dest_ip, self.dest_port,
                        "send", self.session_send, tags,
                        fields, session_id, self.machine.signature
                    )
                    logger.warning(event)
        else:
            if action == "disconnect":
                fields['duration'] = time.time() - self.start_time
            event = UHPEvent(
                self.src_ip, self.src_port,
                self.dest_ip, self.dest_port,
                action, message.rstrip(), tags,
                fields, session_id, self.machine.signature
            )
            logger.warning(event)

# Child class for socketserver.TCPServer to implement TLS
# From https://stackoverflow.com/a/19803457
class SSLTCPServer(socketserver.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 ssl_version=ssl.PROTOCOL_TLSv1_2,
                 bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile  = keyfile
        self.ssl_version = ssl_version

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile = self.certfile,
                                 keyfile = self.keyfile,
                                 ssl_version = self.ssl_version)
        return connstream, fromaddr

class SSLThreadedTCPServer(socketserver.ThreadingMixIn, SSLTCPServer):
    pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class JSONFormatter(logging.Formatter):
    """
    @summary: logging Formatter to emit JSON records
    """
    def __init__(self, timestamp_field="timestamp", *args, **kwargs):
        self.timestamp_field = timestamp_field
        self.converter = time.gmtime
        super().__init__(*args, **kwargs)

    def format(self, record):
        record = copy.copy(record)
        # Create a dict from the message and add a timestamp to it
        try:
            msg = record.msg.__dict__
            msg.pop('fields', None)
        except:
            msg = { 'message' : record.msg }
        dt = datetime.fromtimestamp(record.created)
        msg[self.timestamp_field] = dt.strftime(self.datefmt)
        # Remove the message field if it's empty
        if "message" in msg and msg['message'] == None:
            msg.pop('message', None)
        # Turn the message into JSON
        record.msg = json.dumps(msg)
        return super().format(record)

# Filter to make sure only info goes to the JSON log file
class OnlyWarnFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno == logging.WARN

class HPFeedsHandler(logging.Handler):
    def __init__(self, host, port, channel, ident, secret):
        self.channel = channel
        # Ref https://github.com/threatstream/hpfeeds-collector
        try:
            self.publisher = hpfeeds.new(host, port, ident, secret)
        except hpfeeds.FeedException as e:
            logger.error("Feed exception: %s" % e)
            sys.exit(1)
        logger.debug("Connected to %s (%s:%s)" % (self.publisher.brokername, host, port))
        super().__init__()

    def emit(self, record):
        msg = self.format(record)
        self.publisher.publish(self.channel, msg)
        logger.debug("HPF: sent" + msg)

# Make sure the tarpit command line argument looks like <digits>:<digits>
def validate_tarpit_argument(argument):
    if not re.match(r'^\d+:\d+$', argument):
        raise argparse.ArgumentTypeError("tarpit argument must be <bytes>:<seconds>")
    return argument

if __name__ == "__main__":
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file", help="Config file")
    parser.add_argument("port", help="bind port", type=int, nargs='+')
    parser.add_argument("-b", "--bind-host", help="bind host (defaults to 0.0.0.0)",
            default="0.0.0.0")
    parser.add_argument("-H", "--hpfeeds-config", help="config file for hpfeeds logging")
    parser.add_argument("-f", "--file", help="log file (JSON)")
    parser.add_argument("-a", "--auto-machine-dir",
            help="directory to write auto machine configs", default=None)
    parser.add_argument("-y", "--yaml",
            help="write auto machine configs in YAML instead of JSON", action='store_true')
    parser.add_argument("-m", "--max-bytes", type=int,
            help="maximum bytes to log per session", default=0)
    parser.add_argument("-v", "--verbose", help="output debugging information",
            default=False, action="store_true")
    parser.add_argument("-q", "--quiet", help="suppress stdout log output",
            default=False, action="store_true")
    parser.add_argument("-r", "--log-replies", help="log what we return to clients",
            default=False, action="store_true")
    parser.add_argument("-j", "--json", help="log JSON to stdout",
            default=False, action="store_true")
    parser.add_argument("-s", "--log-sessions", 
            help="log sessions as single events rather than one event per line",
            default=False, action="store_true")
    parser.add_argument("-k", "--key-file", help="Key file for TLS")
    parser.add_argument("-c", "--cert-file", help="Certificate file for TLS")
    parser.add_argument("-t", "--tls-version", help="SSL/TLS version [3, 1, 1.1, 1.2, 1.3]")
    parser.add_argument("-T", "--tarpit", type=validate_tarpit_argument,
            help="specify a rate limit as <bytes>:<second> to limit the speed of data returned to clients")

    args = parser.parse_args()

    # Parse TLS arguments
    try:
        # Default to max version of TLS the client supports
        # Works in Python 3.6+
        ssl_version = ssl.PROTOCOL_TLS
    except:
        # Fall back for older Python
        ssl_version = ssl.PROTOCOL_TLSv1_2

    if args.tls_version:
        try:
            if args.tls_version == "1.3":
                ssl_version = ssl.PROTOCOL_TLSv1_3
            if args.tls_version == "1.2":
                ssl_version = ssl.PROTOCOL_TLSv1_2
            elif args.tls_version == "1.1":
                ssl_version = ssl.PROTOCOL_TLSv1_1
            elif args.tls_version == "1.0" or args.tls_version == "1":
                ssl_version = ssl.PROTOCOL_TLSv1
            elif args.tls_version == "3":
                # Requires an older version of openssl
                ssl_version = ssl.PROTOCOL_SSLv3
            else:
                parser.error("Unsupported TLS version: " + args.tls_version)
        except AttributeError:
            print("SSL/TLS v" + args.tls_version + " is not supported by this version of the ssl library.")
            sys.exit(1)

    # TLS certificate and key files
    enable_tls = False
    if args.key_file and not args.cert_file:
        raise RuntimeError("Certificate file (-c) is required if key file is provided")
    elif args.cert_file and not args.key_file:
        raise RuntimeError("Key file (-k) is required if certificate file is provided")
    elif args.cert_file and args.key_file:
        # Check file existence / readability
        try:
            fh = open(args.cert_file)
            fh.close()
            fh = open(args.key_file)
            fh.close()
        except Exception as e:
            print(e)
            sys.exit(1)
        enable_tls = True

    # Configure logging
    logger.setLevel(logging.DEBUG)
    stdout_handler = logging.StreamHandler()
    
    # Output formatter for plain text
    plain_formatter = logging.Formatter(
        '%(asctime)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z'
    )

    # Output formatter for JSON
    json_formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%SZ', timestamp_field='@timestamp')

    # Should stdout be JSON or plain text?
    if args.json:
        stdout_handler.setFormatter(json_formatter)
    else:
        stdout_handler.setFormatter(plain_formatter)

    # Check for verbose/quiet
    if not args.quiet:
        if args.verbose:
            stdout_handler.setLevel(logging.DEBUG)
        else:
            stdout_handler.setLevel(logging.INFO)
        logger.addHandler(stdout_handler)

    # Do we have an output file?
    if args.file:
        file_handler = logging.handlers.TimedRotatingFileHandler(
                args.file,
                when='midnight',
                interval=1,
                backupCount=7
        )
        file_handler.setFormatter(json_formatter)
        # Only log info() to this handler
        file_handler.addFilter(OnlyWarnFilter())
        logger.addHandler(file_handler)
    
    # Enable hpfeeds?
    if args.hpfeeds_config:
        config = configparser.ConfigParser()
        config.read(args.hpfeeds_config)
        hpf = config['hpfeeds']
        hpf_handler = HPFeedsHandler(
            hpf['host'],
            int(hpf['port']),
            hpf['channel'],
            hpf['ident'],
            hpf['secret']
        )
        hpf_handler.setFormatter(json_formatter)
        hpf_handler.setLevel(logging.WARN)
        logger.addHandler(hpf_handler)

    # Read in the config file that defines state transitions
    with open(args.config_file) as f:
        if args.config_file.endswith('yml') or args.config_file.endswith('yaml'):
            config = yaml.safe_load(f.read())
        else:
            config = json.loads(f.read())

    # Check the config for errors
    UniversalHoneyPot.validate(config)
    
    # Parse the tarpit argument
    if args.tarpit:
        tarpit_bytes, tarpit_seconds = args.tarpit.split(':')
    else:
        # If no tarpit values are specified, this just becomes the number of
        # bytes for each read() call of the output string or file that we
        # return to a client
        tarpit_bytes = 1024
        tarpit_seconds = 0

    SSLThreadedTCPServer.allow_reuse_address = True
    for port in args.port:
        if enable_tls:
            server = SSLThreadedTCPServer((args.bind_host, port),
                                    ThreadedTCPRequestHandler, args.cert_file, args.key_file,
                                    ssl_version)
        else:
            server = ThreadedTCPServer((args.bind_host, port),
                          ThreadedTCPRequestHandler)
        ip, port = server.server_address
        # Pass some configuration data to the server object
        server.config = config
        server.log_replies  = args.log_replies
        server.log_sessions = args.log_sessions
        server.auto_machine_dir = args.auto_machine_dir
        server.yaml = args.yaml
        server.max_bytes = args.max_bytes
        server.tarpit_bytes = int(tarpit_bytes)
        server.tarpit_seconds = int(tarpit_seconds)

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info("Listening on {}:{}".format(ip, port))

    while True:
        time.sleep(1)
