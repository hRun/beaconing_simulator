# beaconing_simulator

a python script to simulate malware beaconing in a slightly more sophistocated way than just sending a http get request each x seconds with some jitter


## features

- simulate the beacon halting for a period of time due to the compromised device being switched off / asleep / ...
- simulate the beacon receiving a command from the c2 server: multiple larger responses and larger requests to immitate commands and execution results going back and forth for a few minutes. the beacon then slows down for a while assuming the operator works on the results
- simulate the beacon exfiltrating data: a very large request followed by some silence
- simulate parallel user activity as background noise
- run the simulation in a "log only" mode, not making any actual network requests, but writing a log file which should look similar to what your proxy/etc. would produce
- jitter, intervals and maximum number of requests obviously
- TODO support of multiple protocols
- TODO support of more http methods
- TODO support of round robin c2 servers


## example

```
python beaconing_simulation.py example.com 31 100 --log_only --include_absence 600
```


### resulting message log

```
2025-06-16 16:50:54,033 - INFO - starting simulation...
2025-06-16 16:50:54,036 - INFO - will dispatch 100 requests towards "example.com" with an interval of 31 seconds and 10% jitter before ending the simulation.
2025-06-16 16:50:54,036 - INFO -  background noise as users would generate it will be simulated.
2025-06-16 16:50:54,037 - INFO - 1.250684973081222% of requests will simulate active usage of the c2 channel.
2025-06-16 16:50:54,039 - INFO - 600 minutes of absence (no beacons doe to the device being offline/asleep/...) will be simulated after 72 requests.
2025-06-16 16:50:54,039 - INFO - data exfiltration will be simulated after 92 requests.
2025-06-16 16:50:54,040 - INFO - simulation will run in log-only mode. no actual requests will be dispatched.
2025-06-16 16:50:54,052 - INFO - rolled to simulate command transfer and execution on request #41.
2025-06-16 16:50:54,053 - INFO - reducing beaconing by 130 seconds for the next 3 requests.
2025-06-16 16:50:54,061 - INFO - hit request #72. sleeping for 600 minutes to simulate the device being offline/asleep/....
2025-06-16 16:50:54,066 - INFO - rolled to simulate command transfer and execution on request #88.
2025-06-16 16:50:54,066 - INFO - reducing beaconing by 25 seconds for the next 3 requests.
2025-06-16 16:50:54,067 - INFO - hit request #92. simulating data exfiltration.
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
