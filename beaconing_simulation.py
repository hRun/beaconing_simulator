"""
a script to simulate malware beaconing in a slightly more sophistocated way than just sending a http get request each x seconds with some jitter

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
"""

# TODO simulation of c2 and exfil requires a server-side process to control response sizes. one endpoint for regular small responses, one endpoint for big responses (tool transfer / sending commands) -> size should change after each request, one endpoint for random responses (noise)

import argparse
import logging
import random
import requests
import socket
import string
import threading
import time
import urllib3

from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone
from os                     import getlogin
from sys                    import exit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # we don't care about ssl warnings as we're not exchanging any sensitive data




def approximate_request_size(request) -> int:
    """
    approximate a http request's size for logging. the requests/aiohttp library does not implement this
    dirty implementation, but why not. this is a simple script after all

    Args:
        request: requests library request object to calculate the size of

    Returns:
        int: size of the request ion bytes
    """
    size: int = 0

    try:
        size += len(request.method)
    except Exception:
        pass
    try:
        size += len(request.url)
    except Exception:
        pass
    try:
        size += len('\r\n'.join('{}{}'.format(k, v) for k, v in request.headers.items()))
    except Exception:
        pass
    try:
        size += request.body if request.body else 0
    except Exception:
        pass
    return size


def beacon_sleep():
    """
    let the beacon sleep for the determined interval
    """
    global reduction_count

    # roll jitter and sleep for beaconing interval plus jitter
    jitter = random.uniform(-1.0*(args.interval/100)*args.include_jitter, 1.0*(args.interval/100)*args.include_jitter)
    jitter = 0 if (jitter < 0 and -jitter > args.interval) else jitter  # can't sleep negative time

    if args.log_only:
        global fake_timestamp

        fake_timestamp += timedelta(seconds=args.interval + jitter)

        # sleep additional time, if temporary throttling is active
        if reduction_count > 0:
            fake_timestamp += timedelta(seconds=reduction_time)
            reduction_count -= 1
    else:
        time.sleep(args.interval + jitter)

        # sleep additional time, if temporary throttling is active
        if reduction_count > 0:
            time.sleep(reduction_time)
            reduction_count -= 1


def write_beaconing_log_event(response):
    """
    write the results of the current beacon to the log file

    Args:
        response - http response from the call
    """
    # TODO check response code?
    event_logger.info(f'''\
        "SourceUserName": "{USER}", \
        "DeviceName": "{HOSTNAME}", \
        "DestinationHostName": "{args.destination}", \
        "DestinationIP": "{args.destination}", \
        "RequestMethods": "{args.request_method}", \
        "Protocol": "{args.protocol}", \
        "RequestURL": "{args.protocol.lower()}://{args.destination}/{beaconing_uri}", \
        "SentBytes": {approximate_request_size(response.request)}, \
        "ReceivedBytes": {len(response.body)}'''.replace('    ', ''))


def simulate_c2_log_only_iteration():
    """
    one iteration of the simulation where events are only logged, no actual request is dispatched
    """
    global fake_timestamp

    # TODO this should consist of multiple requests? one for receiving command, one for results later?
    event_logger.info(f'''\
        "TimeGenerated": "{fake_timestamp}", \
        "SourceUserName": "{USER}", \
        "DeviceName": "{HOSTNAME}", \
        "DestinationHostName": "{args.destination}", \
        "DestinationIP": "{args.destination}", \
        "RequestMethods": "{args.request_method}", \
        "Protocol": "{args.protocol}", \
        "RequestURL": "{args.protocol.lower()}://{args.destination}/{command_uri}", \
        "SentBytes": {random.randint(350, 5000)}, \
        "ReceivedBytes": {random.randint(400, 15000)}'''.replace('    ', ''))
    fake_timestamp += timedelta(seconds=random.randint(1, 40))  # seems like appropriate values. can be changed though


def simulate_exfil_log_only_iteration():
    """
    one iteration of the simulation where events are only logged, no actual request is dispatched
    """
    global fake_timestamp

    # TODO chunking?
    exfil_duration = random.randint(60, 600)

    event_logger.info(f'''\
        "TimeGenerated": "{fake_timestamp}", \
        "SourceUserName": "{USER}", \
        "DeviceName": "{HOSTNAME}", \
        "DestinationHostName": "{args.destination}", \
        "DestinationIP": "{args.destination}", \
        "RequestMethods": "{args.request_method}", \
        "Protocol": "{args.protocol}", \
        "RequestURL": "{args.protocol.lower()}://{args.destination}/{exfil_uri}", \
        "SentBytes": {exfil_duration*random.randint(1000, 10000000)}, \
        "ReceivedBytes": {random.randint(400, 15000)}'''.replace('    ', ''))
    fake_timestamp += timedelta(seconds=exfil_duration)  # seems like appropriate values. can be changed though


def simulate_normal_log_only_iteration():
    """
    one iteration of the simulation where events are only logged, no actual request is dispatched
    """
    global fake_timestamp

    event_logger.info(f'''\
        "TimeGenerated": "{fake_timestamp}", \
        "SourceUserName": "{USER}", \
        "DeviceName": "{HOSTNAME}", \
        "DestinationHostName": "{args.destination}", \
        "DestinationIP": "{args.destination}", \
        "RequestMethods": "{args.request_method}", \
        "Protocol": "{args.protocol}", \
        "RequestURL": "{args.protocol.lower()}://{args.destination}/{beaconing_uri}", \
        "SentBytes": {210}, \
        "ReceivedBytes": {360}'''.replace('    ', ''))
    fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


def simulate_c2_iteration():
    """
    one beaconing iteration of the simulation with c2 content
    """
    if args.log_only:
        simulate_c2_log_only_iteration()
    else:
        pass  # TODO requires a server-side


def simulate_exfil_iteration():
    """
    one beaconing iteration of the simulation with data exfiltration
    """
    if args.log_only:
        simulate_exfil_log_only_iteration()
    else:
        pass  # TODO requires a server-side


def simulate_normal_iteration():
    """
    one normal beaconing iteration of the simulation
    """
    global beaconing_uri

    if args.use_dynamic_urls:
        beaconing_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    if args.log_only:
        simulate_normal_log_only_iteration()
    else:
        try:
            if args.request_method == 'POST':
                response = requests.post(
                    f'{args.protocol.lower()}://{args.destination}/{beaconing_uri}',
                    headers={
                        'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                        'accept': '*/*',
                        'cache-control': 'no-cache'
                    },
                    data={'dummykey': 'dummyvalue'},
                    verify=False
                )

                write_beaconing_log_event(response)
            else:
                response = requests.get(
                    f'{args.protocol.lower()}://{args.destination}/{beaconing_uri}',
                    headers={
                        'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                        'accept': '*/*',
                        'cache-control': 'no-cache'
                    },
                    params={'dummykey': 'dummyvalue'},
                    verify=False
                )

                write_beaconing_log_event(response)
        except Exception as e:
            print('oh no :\'( ', e)


def simulate_beaconing():
    """
    main function to control beaconing based on the provided commandline arguments

    Args:
        session: asynchonous http session
    """
    global absent
    global done
    global fake_timestamp
    global reduction_count
    global reduction_time

    for i in range(args.max_requests):
        beacon_sleep()

        # randomly simulate command execution. don't do so during the first 20 intervals
        if COMMAND_RATIO > 0.0 and i > 20:
            if random.uniform(0.0, 99.9) < COMMAND_RATIO:
                message_logger.info(f'rolled to simulate command transfer and execution on request #{i}.')

                simulate_c2_iteration()

                # temporarily increase beaconing interval to simulate the attacker needing less beacons while working on the received data
                reduction_count = random.randint(2, int((args.interval/60)*args.max_requests/50)+1)  # minutes
                reduction_count = int((reduction_count*60) / args.interval)  # intervals
                reduction_time  = random.randint(int(args.interval/10), int(args.interval*5))  # seconds to temporarily increase the beaconing interval by

                message_logger.info(f'reducing beaconing by {reduction_time} seconds for the next {reduction_count} requests.')

                continue

        if ABSENCE_START > 0 and i == ABSENCE_START:
            message_logger.info(f'hit request #{i}. sleeping for {args.include_absence} minutes to simulate the device being offline/asleep/....')

            absent = True

            if args.log_only:
                fake_timestamp += timedelta(minutes=args.include_absence)
            else:
                time.sleep(args.include_absence)

            absent = False
            continue

        if EXFIL_START > 0 and i == EXFIL_START:
            message_logger.info(f'hit request #{i}. simulating data exfiltration.')

            simulate_exfil_iteration()
            continue

        simulate_normal_iteration()

    done = True


def make_background_noise():
    """
    make one or multiple requests simulating normal user activity while a beacon is going
    """
    global fake_timestamp

    while not done:
        # have some random time pass between "user activity"
        if args.log_only:
            fake_timestamp += timedelta(seconds=random.randint(120, 900))
        else:
            time.sleep(random.randint(120, 900))

        if not absent:
            # browser a "legitimate random" subpage in X% of cases, else just go to the home page
            domain    = USER_ACTIVITY_DOMAINS[random.randint(0, len(USER_ACTIVITY_DOMAINS)-1)]
            random_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            random_uri = random_uri if random.randint(0, 100) < 30 else ''

            if args.log_only:
                event_logger.info(f'''\
                    "TimeGenerated": "{fake_timestamp}", \
                    "SourceUserName": "{USER}", \
                    "DeviceName": "{HOSTNAME}", \
                    "DestinationHostName": "{domain}", \
                    "DestinationIP": "{domain}", \
                    "RequestMethods": "{args.request_method}", \
                    "Protocol": "{args.protocol}", \
                    "RequestURL": "{args.protocol.lower()}://{domain}/{random_uri}", \
                    "SentBytes": {random.randint(150, 600)}, \
                    "ReceivedBytes": {random.randint(150, 300000)}'''.replace('    ', ''))
                fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though
            else:
                response = requests.get(
                    f'https://{USER_ACTIVITY_DOMAINS[random.randint(0, len(USER_ACTIVITY_DOMAINS)-1)]}/{random_uri}',
                    headers={
                        'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                        'accept': '*/*',
                        'cache-control': 'no-cache'
                    },
                    verify=False
                )

                event_logger.info(f'''\
                    "SourceUserName": "{USER}", \
                    "DeviceName": "{HOSTNAME}", \
                    "DestinationHostName": "{domain}", \
                    "DestinationIP": "{domain}", \
                    "RequestMethods": "{args.request_method}", \
                    "Protocol": "{args.protocol}", \
                    "RequestURL": "{args.protocol.lower()}://{domain}/{random_uri}", \
                    "SentBytes": {response.request}, \
                    "ReceivedBytes": {len(response.body)}'''.replace('    ', ''))




parser = argparse.ArgumentParser()
parser.add_argument("destination", help="beaconing destination (fqdn or ip)", type=str)  # TODO resolve/lookup for the other one
parser.add_argument("interval", help="default beaconing interval (in seconds)", type=int, default=30)
parser.add_argument("max_requests", help="end the simulation after X requests", type=int, default=720)  # makes a default run time of approximately 6 hours
parser.add_argument("--include_absence", help="make a significant pause of X minutes during the test to simulate the device being offline/sleeping/...", type=int, default=0)
parser.add_argument("--include_commands", help="simulate the beacon receiving instructions from the c2 server (some larger responses, followed by larger requests, followed by temporary slower beaconing)", action="store_true", default=True)
parser.add_argument("--include_exfil", help="simulate the beacon exfiltrating data (similar to --include_commands, but with significantly larger outflow)", action="store_true", default=True)
parser.add_argument("--include_jitter", help="add random jitter to the time intervals between the beaconing requests (maximum percent of interval)", type=int, default=10)
parser.add_argument("--include_noise", help="make semi-random non-beaconing requests in the background to add noise (as user activity would)", action="store_true", default=True)
parser.add_argument("--log_only", help="only write log events as they would be expected from the simulation, don't actually dispatch requests", action="store_true", default=False)
parser.add_argument("--protocol", help="network protocol to use for beaconing communication", type=str, choices=['HTTP', 'HTTPS'], default='HTTP')  # TODO choices=['DNS', 'HTTP', 'TCP', 'UDP', 'WEBSOCKET']
parser.add_argument("--request_method", help="http request method to use for beaconing communication", type=str, choices=['GET', 'POST'], default='GET')
parser.add_argument("--use_dynamic_urls", help="use a new randomly generated path on each request", action="store_true", default=False)
# TODO parser.add_argument("--use_round_robin", help="iterate through a number of destinations instead of using just one (list of fqdns besides the primary one)", type=list)
args = parser.parse_args()


ABSENCE_START: int         = 0
COMMAND_RATIO: float       = 0.0
EXFIL_START: int           = 0
HOSTNAME: str              = socket.gethostname()
USER: str                  = getlogin()  # TODO domain? upn?
absent: bool               = False
beaconing_uri: str         = 'ping'
command_uri: str           = 'command'
done: bool                 = False
exfil_uri: str             = 'exfil'
fake_timestamp: datetime   = datetime.now(timezone.utc)  # expected format is strftime('%m/%d/%Y %H:%M:%S.%.3f %p')
reduction_count: int       = 0
reduction_time:  int       = 0
response                   = None
USER_ACTIVITY_DOMAINS:list = [
    'amazon.com', 'cnn.com', 'github.com', 'google.com', 'instagram.com',
    'justbean.co', 'office.com', 'reddit.com', 'reuters.com', 'theuselessweb.com', 
    'tiktok.com', 'x.com', 'youtube.com', '9gag.com'
]


# set up logger for general messages (file and stdout)
formatter      = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
message_logger = logging.getLogger('messages')

message_logger.setLevel(logging.DEBUG)

fh = ConcurrentRotatingFileHandler('beaconing_simulation_messages.log')
ch = logging.StreamHandler()
fh.setFormatter(formatter)
ch.setFormatter(formatter)
message_logger.addHandler(fh)
message_logger.addHandler(ch)

"""
expected call for logging:
    message_logger.info('whatever you want')
"""


# set up logger for the events which we'd also expect to be logged by an observing proxy (file only)
if args.log_only:
    formatter = logging.Formatter('{ %(message)s}')
else:
    formatter = logging.Formatter('{"TimeGenerated": "%(asctime)s", %(message)s}')

event_logger = logging.getLogger('events')

event_logger.setLevel(logging.DEBUG)

eh = ConcurrentRotatingFileHandler('beaconing_simulation_events.log')
eh.setFormatter(formatter)
event_logger.addHandler(eh)

"""
expected call for logging (all fields are expected)
    event_logger.info('
        "SourceUserName": "DummyUser", 
        "DeviceName": "DummyDeviceName",   # TODO could also get this from the system
        "DestinationHostName": "ActualDestination",  # TODO from arguments
        "DestinationIP": "ActualDestinationIP",
        "RequestMethods": "GET",  # POST, HEAD, SOCKS, TUNNELED, WEBSOCKET, DNS(?), RAW TCP(?), ...
        "Protocol": "HTTP",  # TODO did we actually want/need this?!
        "RequestURL": "ActualUrl",
        "SentBytes": 123, 
        "ReceivedBytes": 123
    ')
if log_only, start with "TimeGenerated": "current_iteration_time",
"""



message_logger.info(f'starting simulation...')

if args.max_requests < 100:
    message_logger.info(f'max_requests was set to {args.max_requests}. it was automatically increased to 100.')
    args.max_requests = 100

if args.include_jitter < 0:
    args.include_jitter = 0

message_logger.info(f'will dispatch {args.max_requests} requests towards "{args.destination}" with an interval of {args.interval} seconds and {args.include_jitter}% jitter before ending the simulation.')
message_logger.info(f'{"" if args.include_noise else "no"} background noise as users would generate it will be simulated.')

if args.include_commands:
    COMMAND_RATIO = random.uniform(0.5, 3.5)  # x percent chance of a request being active usage of the c2 channel. static maximum of X%
    message_logger.info(f'{COMMAND_RATIO}% of requests will simulate active usage of the c2 channel.')

if args.include_absence > 0:
    ABSENCE_START = random.randint(int(args.max_requests*0.4), int(args.max_requests*0.8))  # start absence interval after x requests
    message_logger.info(f'{args.include_absence} minutes of absence (no beacons doe to the device being offline/asleep/...) will be simulated after {ABSENCE_START} requests.')

if args.include_exfil:
    EXFIL_START = random.randint(int(args.max_requests*0.8)+1, args.max_requests)  # start exfiltration simulation after x requests. always after absence
    message_logger.info(f'data exfiltration will be simulated after {EXFIL_START} requests.')

if args.log_only:
    message_logger.info(f'simulation will run in log-only mode. no actual requests will be dispatched.')
else:
    message_logger.info(f'simulation will run at least {round((args.interval/60)*args.max_requests + args.include_absence, 2)} minutes.')
    # TODO do a check whether the destination is reachable




if __name__ == "__main__":
    beaconing_thread = threading.Thread(target=simulate_beaconing, daemon=True)
    beaconing_thread.start()

    noise_thread = threading.Thread(target=make_background_noise, daemon=True)
    noise_thread.start()

    # keep the main thread alive
    try:
        while True:
            time.sleep(1)

            if done:
                exit(0)
    except KeyboardInterrupt:
        pass
