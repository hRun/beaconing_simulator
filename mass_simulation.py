import os
import random
import string
import sys
import threading
import time
 
from pathlib import Path
 
from beaconing_simulation import simulate_beaconing
from http_beacon          import HttpBeacon
from socks_beacon         import SocksBeacon
 
 
 
 
NUMBER_OF_HTTP_GET_SIMULATIONS_TO_RUN = 15
NUMBER_OF_SOCKS_SIMULATIONS_TO_RUN    = 15
 
Path("beaconing_simulation_logs").mkdir(parents=True, exist_ok=True)  # create a logging folder if it doesn't exist in cwd yet
 
 
class CustomArgObject():
    """
    a substitute for the args from the argparse library that the beacon objects would usually expect for initialization
    will roll random values for a simulation upon object initialization
    """
 
    def __init__(self):
        destination_count: int = 1 if random.randint(0, 100) < 50 else random.randint(2, 6)  # 1 domain only in 50% of cases
        self.destinations: str = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 20))) + ['.com', '.cn', '.edu', '.io', '.nl'][random.randint(0, 4)] \
                                 if destination_count == 1 \
                                 else ','.join([''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 20))) + ['.com', '.cn', '.edu', '.io', '.nl'][random.randint(0, 4)] for i in range(destination_count)])

        self.interval: int                  = random.randint(10, 1800)
        self.max_requests: int              = random.randint(720, 2500)
        self.absence: int                   = 0 if random.randint(0, 100) < 70 else random.randint(4*60, 3*24*60)  # simulate 4h-3d absence in 30% of runs
        self.active_c2_ratio: float         = random.uniform(0.1, 3.0)
        self.data_jitter: int               = random.randint(11, 222)
        self.jitter: int                    = random.randint(17, 83)
        self.log_only: bool                 = True
        self.no_c2: bool                    = True if random.randint(0, 100) < 5 else False  # don't simulate active c2 usage in only 5% of runs
        self.no_chunking: bool              = False
        self.no_exfil: bool                 = True if random.randint(0, 100) < 30 else False  # don't simulate data exfiltration in only 30% of runs
        self.no_noise: bool                 = True  # background noise is not necessary for our purposes
        self.protocol: str                  = ['HTTP', 'HTTPS', 'SOCKS'][random.randint(0, 2)]
        self.reduce_interval_after_c2: bool = True if random.randint(0, 100) < 30 else False  # simulate interval reduction after active c2 usage in 30% of runs
        self.response_size: str             = ['NORMAL', 'LARGE'][random.randint(0, 1)] if random.randint(0, 100) < 90 else 'RANDOM'  # rarely use random response sizes as they are unlikely to be used in the real world
        self.request_method: str            = 'GET' if random.randint(0, 100) < 80 else ['POST', 'PUT'][random.randint(0,1)]  # mostly simulate HTTP GET beacons if HTTP was selected
        self.start_time: int                = 1753707644 - random.randint(0, 31536000)  # between 2024-07-28 and 2025-07-28
        self.static_ip: bool                = True if random.randint(0, 100) < 30 else False
        self.use_dynamic_urls: bool         = True if random.randint(0, 100) < 50 else False
        self.round_robin_logic: str         = '1' if random.randint(0, 100) < 60 else ['RANDOM', '5', '10', '50', '100'][random.randint(0, 4)]
 
 
for i in range(NUMBER_OF_HTTP_GET_SIMULATIONS_TO_RUN + NUMBER_OF_SOCKS_SIMULATIONS_TO_RUN):
    # TODO make sure we have at least one fast, medium and slow beacon for each type of c2 channel
    args = CustomArgObject()  # roll random arguments
 
    if i <= NUMBER_OF_HTTP_GET_SIMULATIONS_TO_RUN:
        beacon = HttpBeacon(args)
    else:
        beacon = SocksBeacon(args)
 
    try:
        simulate_beaconing(beacon)
    except KeyboardInterrupt:
        pass
 
    beacon.message_logger.info(f'done. have a nice day :)')
    beacon.clean_up()
 
    for handler in beacon.message_logger.handlers:
        handler.close()
        beacon.message_logger.removeHandler(handler)
        # TODO somehow the second log handler for writing to file is not destroyed, causing duplicate events to be logged?!
    for handler in beacon.event_logger.handlers:
        handler.close()
        beacon.event_logger.removeHandler(handler)
 
    # move written log files to the new logging folder with good naming
    os.replace('beaconing_simulation_events.log', f'beaconing_simulation_logs/run{i}_{args.interval}s_{args.max_requests}reqs_{args.protocol}_rr-{args.round_robin_logic}_events.log')
    os.replace('beaconing_simulation_messages.log', f'beaconing_simulation_logs/run{i}_{args.interval}s_{args.max_requests}reqs_{args.protocol}_rr-{args.round_robin_logic}_messages.log')
