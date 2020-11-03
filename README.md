# Universal Honey Pot
Universal Honey Pot is a medium interaction honeypot that allows defenders to
quickly implement line-based TCP protocols with a simple JSON or YAML
configuration.
## Why?
Threats evolve quickly, and writing traditional honeypots is a pain.  Defenders
start from scratch writing networking, logging, and protocol emulation code,
and then they still have to integrate their new honeypot with existing systems.
In practice, few new honeypots ever get written for those reasons.

UHP provides all the networking and logging, and it outputs JSON or publishes
to hpfeeds for quick integration.  It makes emulating new protocols a simple
matter of creating some JSON or YAML, or it can even run with a generic config
and write new skeleton emulations all by itself based on the input it receives.
## Usage
```
usage: uhp.py [-h] [-b BIND_HOST] [-H HPFEEDS_CONFIG] [-f FILE]
              [-a AUTO_MACHINE_DIR] [-y] [-m MAX_BYTES] [-v] [-q] [-r] [-j]
              [-s] [-k KEY_FILE] [-c CERT_FILE] [-t TLS_VERSION]
              config_file port [port ...]

positional arguments:
  config_file           Config file
  port                  bind port

optional arguments:
  -h, --help            show this help message and exit
  -b BIND_HOST, --bind-host BIND_HOST
                        bind host (defaults to 0.0.0.0)
  -H HPFEEDS_CONFIG, --hpfeeds-config HPFEEDS_CONFIG
                        config file for hpfeeds logging
  -f FILE, --file FILE  log file (JSON)
  -a AUTO_MACHINE_DIR, --auto-machine-dir AUTO_MACHINE_DIR
                        directory to write auto machine configs
  -y, --yaml            write auto machine configs in YAML instead of JSON
  -m MAX_BYTES, --max-bytes MAX_BYTES
                        maximum bytes to log per session
  -v, --verbose         output debugging information
  -q, --quiet           suppress stdout log output
  -r, --log-replies     log what we return to clients
  -j, --json            log JSON to stdout
  -s, --log-sessions    log sessions as single events rather than one event
                        per line
  -k KEY_FILE, --key-file KEY_FILE
                        Key file for TLS
  -c CERT_FILE, --cert-file CERT_FILE
                        Certificate file for TLS
  -t TLS_VERSION, --tls-version TLS_VERSION
                        SSL/TLS version [3, 1, 1.1, 1.2, 1.3]
```
## Configuration
The UHP basic configuration contains two data elements:
* banner - (optional) UHP provides this text to every connecting client.
* states - The list of machine states and the rules to transition between them.

Each state contains a list of transition rules.  A transition rule has three
basic elements, all of which are optional:
* pattern - A regular expression.  The machine executes the first matching rule.
* output - This text will be returned to the client if the pattern  matches.
* next - The new state for the machine to enter on a match.  If no
         next state is provided, the machine remains in its current state.

There are three special states:

* _START - Every machine starts in this state, and it must be defined.
* _SHARED - (optional) The _SHARED state is for common transition rules that
            apply to all states.  If no rules in a given state fire, the machine
            next checks all the rules in the _SHARED state.
* _END - Transitioning to the _END state signals UHP to close the 
         connection.
         
## Example Configuration
This diagram shows an example configuration for a simple POP3 honeypot.  When a
client connects, UHP issues a banner of "+OK Ready" to the client and moves
into its initial state.  If the client sends a "PASS ..." command in this
initial state without first sending a username, UHP responds back with "-ERR No
username given" and remains in the initial state.  If the client sends "USER
...", UHP replies back with "+OK" and moves into a new state in which the
username has been accepted.  In this new state, UHP responds to a "PASS ..."
command with an invalid password error.

![POP3 State Diagram](https://mattcarothers.github.io/uhp/pop3-example.png)

This is the corresponding JSON configuration file:
```
{
    "banner" : "+OK Ready\r\n",
    "states" : {
        "_START" : [
            {
                "pattern" : "^PASS",
                "output"  : "-ERR No username given.\r\n"
            }
        ],
        "user_accepted" : [
            {
                "pattern" : "^PASS",
                "output"  : "-ERR invalid user name or password.\r\n",
                "next"    : "_END"
            }
        ],
        "_SHARED" : [
            {
                "pattern" : "^USER",
                "output"  : "+OK\r\n",
                "next"    : "user_accepted"
            },
            {
                "pattern" : "^QUIT",
                "output"  : "+OK Logging out\r\n",
                "next"    : "_END"
            },
            {
                "pattern" : ".",
                "output"  : "-ERR Unknown command.\r\n"
            }
        ]
    }
}
```

See [configs/pop3.yml](pop3.yml) for a more fully-featured POP3 honeypot.

Additional elements (see Dynamic Output and Advanced Configuration below):
* match_case - (rule) This flag makes the regex match case sensitive.
* tags - (rule/global) An array of tags to add to the log
* fields - (rule/global) A dictionary of keys and values to add to the log
* datefmt - (rule/global) a strftime() string to format the {date} output

## Dynamic Output
If a transition rule pattern contains groupings, matches can be used in output.
Example rule:
```
{
    "pattern" : "^HELO (\\S+)",
    "output"  : "250 localhost.localdomain pleased to meet you, {match[0]}\r\n",
    "next"    : "helo_accepted"
}
```
Named subgroups work as well:
```
{
    "pattern" : "^EHLO (?P<hostname>\\S+)",
    "output"  : "250 localhost.localdomain pleased to meet you, {hostname}\r\n",
    "next"    : "helo_accepted"
}
```
Note that the JSON parser treats back slashes as escape characters, so double
back slashes must be used for regular expressions.

Additionally, a field name called {date} contains the current date and time.
Set "datefmt" in the server config or in an individual transition rule to
control the format.
Examples:
```
{
    "states" : {
        "_START" : [
            {
                "pattern" : "^(GET|POST|HEAD|PUT|DELETE)",
                "output"  : "HTTP/1.1 404 Not Found\r\nServer: nginx/1.13.4\r\nDate: {date}\r\n",
                "datefmt" : "%a, %d %b %Y %H:%M:%S GMT",
                "next"    : "_END"
            }
        ]
    }
}
```
```
{
    "banner" : "It's {date}.  Do you know where your children are?",
    "datefmt" : "%Y-%m-%dT%H:%M:%SZ",
    "states" : {
        "_START" : [ ]
    }
}
```
## Session Logging
By default, UHP logs every line of input separately.  If you wish to log
the client's entire input as a single event, use the -s flag.

Standard logging:
```
{
  "message": "",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "connect",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "GET / HTTP/1.1",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "recv",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "Host: localhost:80",
  "tags": [
    "am_ignore"
  ],
  "dest_ip": "127.0.0.1",
  "action": "recv",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "User-Agent: curl/7.47.0",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "recv",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "Accept: */*",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "recv",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "recv",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
{
  "message": "",
  "tags": [],
  "dest_ip": "127.0.0.1",
  "action": "disconnect",
  "src_port": 38050,
  "dest_port": 80,
  "session_id": "798ce8f4-4b1b-47e8-ad8e-97f919642782",
  "@timestamp": "2017-10-28T00:27:36Z",
  "src_ip": "127.0.0.1"
}
```

Session logging:
```
{
  "dest_port": 80,
  "action": "recv",
  "src_ip": "127.0.0.1",
  "@timestamp": "2017-10-28T00:30:08Z",
  "src_port": 38056,
  "tags": [],
  "dest_ip": "127.0.0.1",
  "session_id": "ed734d81-9fd7-4cac-9359-8c734b3e29db",
  "message": "GET / HTTP/1.1\r\nHost: localhost:80\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n"
}
```

Session logging produces significantly fewer events but may make it more
difficult to cluster common strings between diverse attackers.

## Advanced Configuration
You may wish to set custom fields in the JSON output or override the defaults.
You may do so by adding a "fields" dictionary either globally or as part of a
specific rule.  Example:
```
{
    "datefmt" : "%a, %d %b %Y %H:%M:%S GMT",
    "fields"  : {
        "app"      : "uhp",
        "emulated" : "nginx"
    },
    "states" : {
        "_START" : [
            {
                "pattern" : "^(GET|POST|PUT|DELETE|HEAD|OPTIONS)( .*)",
                "fields"  : {
                    "uri"  : "{match[0]}{match[1]}"
                },
                "next"    : "valid_command"
            },
            {
                "pattern" : ".",
                "output"  : "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.13.4\r\nDate: {date}\r\nConnection: close\r\n",
                "next"    : "_END"
            }
        ],
        "valid_command" : [
            {
                "pattern" : "^User-Agent: ?(.*)",
                "fields"  : {
                    "ua"  : "{match[0]}"
                }
            },
            {
                "pattern" : "^$",
                "output"  : "HTTP/1.1 404 Not Found\r\nServer: nginx/1.13.4\r\nDate: {date}\r\nConnection: close\r\n",
                "next"    : "_END"
            }
        ]
    }
}
```
Note that fields persist per session, so a field you set in one state will
continue to be logged in future states.  Also note that you can use this to
override built in fields.  For example, this hides your honeypot's ip address:
```
{
    "fields" : {
        "dest_ip" : "0.0.0.0"
    },
    "states" : {
        "_START" : [ ]
    }
}
```
## Auto Config Generation
Using the -a flag, UHP can automatically generate new state machines
based on client input.  Each line supplied by the client creates a new state,
and the machine writes the new configuration at the end of the session.  The new
configuration file will be named *SourceIP*-*DestPort*-*MD5ofInput*.

You may wish to ignore certain input lines that you expect to vary from client
to client or server to server in order to make the signatures more general.  Do
do so, add the "am_ignore" tag to the transition rule you wish the machine to
ignore.  Here is an example configuration that logs input until a blank line is
received and ignores Host headers:

```
{
    "states" : {
        "_START" : [
            {
                "pattern" : "^Host:",
                "tags"    : [ "am_ignore" ]
            },
            {
                "pattern" : "^$",
                "next"    : "_END"
            }
        ]
    }
}
```
This is a new skeleton machine generated by running curl against the above
configuration:
```
{
    "states": {
        "_START": [
            {
                "next": "1",
                "pattern": "GET / HTTP/1.1"
            }
        ],
        "1": [
            {
                "next": "2",
                "pattern": "User-Agent: curl/7.47.0"
            }
        ],
        "2": [
            {
                "next": "3",
                "pattern": "Accept: */*"
            }
        ],
        "3": [
            {
                "next": "_END",
                "pattern": ""
            }
        ]
    }
}
```
