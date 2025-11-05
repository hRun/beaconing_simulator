"""
a script to simulate malware beaconing in a slightly more sophistocated way than just sending a http get request each x seconds with some jitter

features:
    - simulate the beacon halting for a period of time due to the compromised device being switched off / asleep / ...
    - simulate the beacon receiving a command from the c2 server: multiple larger responses and larger requests to immitate commands and execution results going back and forth for a few minutes. the beacon then slows down for a while assuming the operator works on the results
    - simulate the beacon exfiltrating data: a very large request followed by some silence 
    - simulate parallel user activity as background noise
    - run the simulation in a "log only" mode, not making any actual network requests, but writing a log file which should look similar to what your proxy/etc. would produce
    - jitter, intervals and maximum number of requests obviously, round robin, multiple protocols, etc.
"""

# TODO simulation of c2 and exfil requires a server-side process to control response sizes. one endpoint for regular small responses, one endpoint for big responses (tool transfer / sending commands) -> size should change after each request, one endpoint for random responses (noise)

import argparse
import random
import threading
import time

from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone
from sys                    import exit

from http_beacon      import HttpBeacon
from socks_beacon     import SocksBeacon
from websocket_beacon import WebsocketBeacon




def simulate_beaconing(beacon):
    """
    main function to control beaconing based on the provided commandline arguments

    Args:
        session: asynchonous http session
    """
    round_robin_tracker = 1

    for i in range(beacon.args.max_requests):
        beacon.sleep()

        # randomly simulate command execution. don't do so during the first 20 intervals
        if beacon.COMMAND_RATIO > 0.0 and i > 20:
            if random.uniform(0.00, 99.99) < beacon.COMMAND_RATIO:
                beacon.message_logger.info(f'rolled to simulate command transfer and execution on request #{i}.')

                beacon.c2_iteration()
                beacon.discovery_phase = False  # assume a discovery phase for the first c2 usage where output will be larger than during subsequent usage

                # temporarily increase beaconing interval to simulate the attacker needing less beacons while working on the received data
                if beacon.args.reduce_interval_after_c2:
                    beacon.reduction_count = random.randint(2, int((beacon.args.interval/60)*beacon.args.max_requests/75)+1)  # minutes
                    beacon.reduction_count = int((beacon.reduction_count*60) / beacon.args.interval)  # intervals
                    beacon.reduction_time  = random.randint(int(beacon.args.interval/10), int(beacon.args.interval*5))  # seconds to temporarily increase the beaconing interval by

                    beacon.message_logger.info(f'reducing beaconing by {beacon.reduction_time} seconds for the next {beacon.reduction_count} requests.')
                continue
        if beacon.ABSENCE_START > 0 and i == beacon.ABSENCE_START:
            beacon.message_logger.info(f'hit request #{i}. sleeping for {beacon.args.absence} minutes to simulate the device being offline/asleep/....')

            beacon.absent = True

            if beacon.args.log_only:
                beacon.fake_timestamp += timedelta(minutes=beacon.args.absence)
            else:
                time.sleep(beacon.args.absence)

            beacon.absent = False
            continue
        if beacon.EXFIL_START > 0 and i == beacon.EXFIL_START:
            beacon.message_logger.info(f'hit request #{i}. simulating data exfiltration.')

            beacon.exfil_iteration()
            continue
        # only relevant for the HTTPSxSOCKS mode
        if hasattr(beacon, 'SOCKS_REQUESTS'):
            if i in beacon.SOCKS_REQUESTS:
                beacon.message_logger.info(f'hit request #{i}. simulating temporary usage of device as socks proxy.')

                beacon.socks_iteration()
                continue

        beacon.normal_iteration()

        if beacon.args.round_robin_logic == '1':
            beacon.next_destination()
        elif beacon.args.round_robin_logic == '5':
            if round_robin_tracker == 5:
                beacon.next_destination()
                round_robin_tracker = 1
        elif beacon.args.round_robin_logic == '10':
            if round_robin_tracker == 10:
                beacon.next_destination()
                round_robin_tracker = 1
        elif beacon.args.round_robin_logic == '50':
            if round_robin_tracker == 50:
                beacon.next_destination()
                round_robin_tracker = 1
        elif beacon.args.round_robin_logic == '100':
            if round_robin_tracker == 100:
                beacon.next_destination()
                round_robin_tracker = 1
        elif beacon.args.round_robin_logic == 'RANDOM':
            if random.randint(1, 100) < 20:
                beacon.next_destination()

        round_robin_tracker += 1

    beacon.done = True


def make_background_noise(beacon):
    """
    make one or multiple requests simulating normal user activity while a beacon is going
    """
    while not beacon.done:
        # have some random time pass between "user activity"
        if beacon.args.log_only:
            beacon.fake_timestamp += timedelta(seconds=random.randint(120, 1800))
        else:
            time.sleep(random.randint(120, 1800))

        if not beacon.absent:
            domain = beacon.USER_ACTIVITY_DOMAINS[random.randint(0, len(beacon.USER_ACTIVITY_DOMAINS)-1)]

            for i in range(1, random.randint(2, 8)): # make up to X requests right after one another (not for DNS)
                if beacon.args.log_only:
                    beacon.noise_log_only(domain)
                else:
                    beacon.noise(domain)




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destinations", help="one or more beaconing destination. i.e. the c2 servers (fqdns or ips). provide multiple destinations as comma-separated list", type=str)
    parser.add_argument("interval", help="default beaconing interval (in seconds). default is 30 seconds", type=int, default=30)
    parser.add_argument("max_requests", help="end the simulation after X requests. default is 720 requests, equating to ~6 hours with a 30 second interval", type=int, default=720)
    parser.add_argument("--absence", help="make a significant pause of X minutes during the test to simulate the device being offline/sleeping/... default is no absence", type=int, default=0)
    parser.add_argument("--active_c2_ratio", help="the percentage of requests which should simulate active usage of the c2 channel. i.e. command and result exchange. default is between 0.1 and 3 percent", type=float, default=0.0)
    parser.add_argument("--cap_data_jitter", help="add upper an lower limits to the amount of data jitter (in bytes) than will be applied. syntax: lower_limit,upper_limit (e.g. 1000,1500). default is no limits", type=str)
    parser.add_argument("--data_jitter", help="add random jitter to the request size (also to response sizes if log_only is set) in percent. default is 11 percent", type=int, default=11)
    parser.add_argument("--jitter", help="add random jitter to the time intervals between the beaconing requests (in percent of intervals). default is 17 percent", type=int, default=17)
    parser.add_argument("--log_only", help="only write log events as they would be expected from the simulation, don't actually dispatch requests. default is to make real requests", action="store_true", default=False)
    parser.add_argument("--max_socks_sessions", help="if protocol is set to HTTPSxSOCKS, start up to this many socks sessions over the duration of the beacon", type=int, default=4)
    parser.add_argument("--no_c2", help="don't simulate the beacon receiving instructions from the c2 server (i.e. some larger responses, followed by larger requests, followed by temporary slower beaconing). default is to simulate c2 activity", action="store_true", default=False)
    parser.add_argument("--no_chunking", help="don't use chunking for http requests. i.e. send one large one instead of multiple small requests. default is to use chunking as many server have maximum sizes they handle", action="store_true", default=False)
    parser.add_argument("--no_exfil", help="don't simulate the beacon exfiltrating data (similar to c2, but with significantly larger outflow). default is to simulate data exfiltration", action="store_true", default=False)
    parser.add_argument("--no_noise", help="don't make semi-random, semi-realistic non-beaconing requests in the background to add noise (as user activity would). default is to make background noise", action="store_true", default=False)
    parser.add_argument("--protocol", help="network protocol to use for beaconing communication. default is http", type=str, choices=['HTTP', 'HTTPS', 'HTTPSxSOCKS', 'SOCKS', 'WEBSOCKET'], default='HTTP')  # TODO choices=['DNS', 'TCP', 'UDP', '...']
    parser.add_argument("--reduce_interval_after_c2", help="reduce the polling interval after an active session, simulating how higher stealth could be achieved while the operator works on obtained data", action="store_true", default=False)
    parser.add_argument("--response_size", help="if log_only is set, set the http response size range to use. this is to mimic different malleable profile configurations (e.g. a profile which returns a legitimate-looking web page vs. one that returns the bare minimum)", type=str, choices=['NORMAL', 'LARGE', 'RANDOM'], default='NORMAL')
    parser.add_argument("--request_method", help="if using http, the request method to use for beaconing. mix will use get for requests, post for responses. default is get", type=str, choices=['GET', 'POST', 'PUT', 'MIXED'], default='GET')  # TODO HEAD?
    parser.add_argument("--round_robin_logic", help="set the logic to iterate destinations when multiple were provided. switch domains after every x requests or randomly", type=str, choices=['RANDOM', '1', '5', '10', '50', '100'], default='1')
    parser.add_argument("--start_time", help="if log_only is set, set the start time of the fake simulation (epoch time stamp expected). otherwise the simulation will start at the current time and end in the future", type=int, default=0)
    parser.add_argument("--static_ip", help="a domain might resolve to multiple ips (e.g. when a cdn is used). set this argument to statically log the first observed ip. default is to log a random ip from the set", action="store_true", default=False)
    parser.add_argument("--static_source", help="write log events as originating from the statically set source ip or fqdn. default is to look up and use the local device's name", type=str)
    parser.add_argument("--static_user", help="write log events as originating from the statically set user. default is to look up and use the current user's name", type=str)
    parser.add_argument("--use_dynamic_urls", help="if using http, use a new randomly generated uri path on each request. default is false", action="store_true", default=False)
    args   = parser.parse_args()
    beacon = None


    if args.protocol in ['HTTP', 'HTTPS']:
        beacon = HttpBeacon(args)
    elif args.protocol == 'HTTPSxSOCKS':
        beacon = HttpBeacon(args)
    elif args.protocol == 'DNS':
        pass  # TODO
    elif args.protocol == 'TCP':
        pass  # TODO
    elif args.protocol == 'UDP':
        pass  # TODO
    elif args.protocol == 'SOCKS':
        beacon = SocksBeacon(args)
    elif args.protocol == 'WEBSOCKET':
        beacon = WebsocketBeacon(args)

    beaconing_thread = threading.Thread(target=simulate_beaconing, args=(beacon,), daemon=True)
    beaconing_thread.start()

    if not args.no_noise:
        noise_thread = threading.Thread(target=make_background_noise, args=(beacon,), daemon=True)
        noise_thread.start()

    # keep the main thread alive
    try:
        while True:
            time.sleep(1)

            if beacon.done:
                beacon.message_logger.info(f'done. have a nice day :)')
                beacon.clean_up()
                exit(0)
    except KeyboardInterrupt:
        beacon.clean_up()
        pass
