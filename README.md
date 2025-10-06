# beaconing_simulator

a python script to simulate malware beaconing in a slightly more sophistocated way than just sending a http get request each x seconds with some jitter


## features

- simulate the beacon halting for a period of time due to the compromised device being switched off / asleep / ...
- simulate the beacon receiving a command from the c2 server: multiple larger responses and larger requests to immitate commands and execution results going back and forth for a few minutes. the beacon then slows down for a while assuming the operator works on the results
- simulate the beacon exfiltrating data: a very large request followed by some silence
- simulate usage of round robin in different modes
- simulate parallel user activity as background noise
- run the simulation in a "log only" mode, not making any actual network requests, but writing a log file which should look similar to what your proxy/etc. would produce
- jitter, intervals and maximum number of requests obviously
- support of multiple protocols and http methods (more tbd)


## usage

```
usage: beaconing_simulation.py [-h] [--absence ABSENCE] [--active_c2_ratio ACTIVE_C2_RATIO] [--data_jitter DATA_JITTER] [--jitter JITTER] [--log_only] [--no_c2] [--no_chunking] [--no_exfil] [--no_noise]
                               [--protocol {HTTP,HTTPS,SOCKS,WEBSOCKET}] [--reduce_interval_after_c2] [--response_size {NORMAL,LARGE,RANDOM}] [--request_method {GET,POST,PUT,MIXED}]
                               [--round_robin_logic {RANDOM,1,5,10,50,100}] [--start_time START_TIME] [--static_ip] [--use_dynamic_urls]
                               destinations interval max_requests

positional arguments:
  destinations          one or more beaconing destination. i.e. the c2 servers (fqdns or ips). provide multiple destinations as comma-separated list
  interval              default beaconing interval (in seconds). default is 30 seconds
  max_requests          end the simulation after X requests. default is 720 requests, equating to ~6 hours with a 30 second interval

options:
  -h, --help            show this help message and exit
  --absence ABSENCE     make a significant pause of X minutes during the test to simulate the device being offline/sleeping/... default is no absence
  --active_c2_ratio ACTIVE_C2_RATIO
                        the percentage of requests which should simulate active usage of the c2 channel. i.e. command and result exchange. default is between 0.1 and 3 percent
  --cap_data_jitter CAP_DATA_JITTER
                        add upper an lower limits to the amount of data jitter (in bytes) than will be applied. syntax: lower_limit,upper_limit (e.g. 1000,1500). default is no limits
  --data_jitter DATA_JITTER
                        add random jitter to the request size (also to response sizes if log_only is set) in percent. default is 11 percent
  --jitter JITTER       add random jitter to the time intervals between the beaconing requests (in percent of intervals). default is 17 percent
  --log_only            only write log events as they would be expected from the simulation, don't actually dispatch requests. default is to make real requests
  --no_c2               don't simulate the beacon receiving instructions from the c2 server (i.e. some larger responses, followed by larger requests, followed by temporary slower beaconing). default is to
                        simulate c2 activity
  --no_chunking         don't use chunking for http requests. i.e. send one large one instead of multiple small requests. default is to use chunking as many server have maximum sizes they handle
  --no_exfil            don't simulate the beacon exfiltrating data (similar to c2, but with significantly larger outflow). default is to simulate data exfiltration
  --no_noise            don't make semi-random, semi-realistic non-beaconing requests in the background to add noise (as user activity would). default is to make background noise
  --protocol {HTTP,HTTPS,SOCKS,WEBSOCKET}
                        network protocol to use for beaconing communication. default is http
  --reduce_interval_after_c2
                        reduce the polling interval after an active session, simulating how higher stealth could be achieved while the operator works on obtained data
  --response_size {NORMAL,LARGE,RANDOM}
                        if log_only is set, set the http response size range to use. this is to mimic different malleable profile configurations (e.g. a profile which returns a legitimate-looking web page vs.
                        one that returns the bare minimum)
  --request_method {GET,POST,PUT,MIXED}
                        if using http, the request method to use for beaconing. mix will use get for requests, post for responses. default is get
  --round_robin_logic {RANDOM,1,5,10,50,100}
                        set the logic to iterate destinations when multiple were provided. switch domains after every x requests or randomly
  --start_time START_TIME
                        if log_only is set, set the start time of the fake simulation (epoch time stamp expected). otherwise the simulation will start at the current time and end in the future
  --static_ip           a domain might resolve to multiple ips (e.g. when a cdn is used). set this argument to statically log the first observed ip. default is to log a random ip from the set
  --static_source STATIC_SOURCE
                        write log events as originating from the statically set source ip or fqdn. default is to look up and use the local device's name
  --static_user STATIC_USER
                        write log events as originating from the statically set user. default is to look up and use the current user's name
  --use_dynamic_urls    if using http, use a new randomly generated uri path on each request. default is false
```


## example

```
python beaconing_simulation.py example.com 31 100 --log_only --absence 600
```


### resulting message log

```
2025-10-06 15:29:46,812 - INFO - starting simulation...
2025-10-06 15:29:46,820 - INFO - will dispatch 100 requests towards "example.com" with an interval of 31 seconds and 17% jitter before ending the simulation.
2025-10-06 15:29:46,821 - INFO - background noise as users would generate it will be simulated.
2025-10-06 15:29:46,821 - INFO - 0.828% of requests will simulate active usage of the c2 channel.
2025-10-06 15:29:46,822 - INFO - 600 minutes of absence (no beacons due to the device being offline/asleep/...) will be simulated after 76 requests.
2025-10-06 15:29:46,822 - INFO - data exfiltration will be simulated after 81 requests.
2025-10-06 15:29:46,823 - INFO - simulation will run in log-only mode. no actual requests will be dispatched. this should be done in a few seconds.
2025-10-06 15:29:46,824 - INFO - rolled a default http request size of 7028 bytes and a default http response size of 2580 bytes. will apply 11% jitter. jitter will not be capped if provided limits are reached.
2025-10-06 15:29:46,871 - INFO - hit request #76. sleeping for 600 minutes to simulate the device being offline/asleep/....
2025-10-06 15:29:46,873 - INFO - hit request #81. simulating data exfiltration.
2025-10-06 15:29:47,826 - INFO - done. have a nice day :)
```


### resulting event log

```
{ "TimeGenerated": "2025-06-16 14:51:26.404828+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:02:09.012620+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:02:42.362926+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:01:37.404828+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "justbean.co", "DestinationIP": "justbean.co", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://justbean.co/", "SentBytes": 427, "ReceivedBytes": 274888}
{ "TimeGenerated": "2025-06-16 15:05:20.746365+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "reddit.com", "DestinationIP": "reddit.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://reddit.com/", "SentBytes": 258, "ReceivedBytes": 61901}
{ "TimeGenerated": "2025-06-16 15:03:15.565365+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:18:36.974670+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:18:07.142365+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "theuselessweb.com", "DestinationIP": "theuselessweb.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://theuselessweb.com/", "SentBytes": 562, "ReceivedBytes": 209214}
{ "TimeGenerated": "2025-06-16 15:19:05.260722+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-16 15:33:43.578722+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "amazon.com", "DestinationIP": "amazon.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://amazon.com/", "SentBytes": 382, "ReceivedBytes": 284151}

[...]

{ "TimeGenerated": "2025-06-16 21:26:03.041006+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "google.com", "DestinationIP": "google.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://google.com/", "SentBytes": 245, "ReceivedBytes": 102703}
{ "TimeGenerated": "2025-06-16 21:26:03.041006+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/command", "SentBytes": 2926, "ReceivedBytes": 8274}
{ "TimeGenerated": "2025-06-16 21:30:21.159006+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "justbean.co", "DestinationIP": "justbean.co", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://justbean.co/", "SentBytes": 233, "ReceivedBytes": 198953}
{ "TimeGenerated": "2025-06-16 21:43:09.487006+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "cnn.com", "DestinationIP": "cnn.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://cnn.com/", "SentBytes": 213, "ReceivedBytes": 169162}
{ "TimeGenerated": "2025-06-16 21:55:28.629006+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "google.com", "DestinationIP": "google.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://google.com/", "SentBytes": 472, "ReceivedBytes": 93558}
{ "TimeGenerated": "2025-06-16 21:58:06.869067+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}

[...]

{ "TimeGenerated": "2025-06-17 02:16:10.010439+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "cnn.com", "DestinationIP": "cnn.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://cnn.com/", "SentBytes": 439, "ReceivedBytes": 299971}
{ "TimeGenerated": "2025-06-17 02:21:55.657478+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "github.com", "DestinationIP": "github.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://github.com/", "SentBytes": 184, "ReceivedBytes": 211760}
{ "TimeGenerated": "2025-06-17 12:22:26.739430+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-17 12:28:45.990430+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "google.com", "DestinationIP": "google.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://google.com/zn8UG2UeZCPLxtvO", "SentBytes": 368, "ReceivedBytes": 251754}

[...]

{ "TimeGenerated": "2025-06-17 15:50:54.260255+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/exfil", "SentBytes": 695807044, "ReceivedBytes": 13902}
{ "TimeGenerated": "2025-06-17 16:05:37.394255+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "instagram.com", "DestinationIP": "instagram.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://instagram.com/7CE4Ry8LImZ4qxjD", "SentBytes": 256, "ReceivedBytes": 234257}
{ "TimeGenerated": "2025-06-17 16:08:47.548188+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
{ "TimeGenerated": "2025-06-17 16:11:26.801188+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "justbean.co", "DestinationIP": "justbean.co", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://justbean.co/", "SentBytes": 551, "ReceivedBytes": 110101}
{ "TimeGenerated": "2025-06-17 16:11:57.480734+00:00", "SourceUserName": "h", "DeviceName": "DESKTOP-P1DTAD0", "DestinationHostName": "example.com", "DestinationIP": "example.com", "RequestMethods": "GET", "Protocol": "HTTP", "RequestURL": "http://example.com/ping", "SentBytes": 210, "ReceivedBytes": 360}
```
