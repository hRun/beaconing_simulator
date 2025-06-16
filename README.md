# beaconing_simulator
a python script to simulate malware beaconing in a slightly more sophistocated way than just sending a http get request each x seconds with some jitter

features:
    - simulate the beacon halting for a period of time due to the compromised device being switched off / asleep / ...
    - simulate the beacon receiving a command from the c2 server: a larger response to a request followed by a larger request containing the results after a while. the beacon then slows down for a while assuming the operator works on the results
    - simulate the beacon exfiltrating data: a very large request followed by some silence
    - simulate parallel user activity as background noise
    - run the simulation in a "log only" mode, not making any actual network requests, but writing a log file which should look similar to what your proxy/etc. would produce
    - jitter, intervals and maximum number of requests obviously
    - TODO support of multiple protocols
    - TODO support of more http methods
    - TODO support of round robin c2 servers
