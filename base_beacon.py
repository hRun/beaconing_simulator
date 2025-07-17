import abc
import logging
import random
import socket
import string
import time

from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone
from os                     import getlogin




class Beacon():
    def __init__(self, args):
        # set up logger for general messages (file and stdout)
        formatter           = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.message_logger = logging.getLogger('messages')

        self.message_logger.setLevel(logging.DEBUG)

        fh = ConcurrentRotatingFileHandler('beaconing_simulation_messages.log')
        ch = logging.StreamHandler()
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        self.message_logger.addHandler(fh)
        self.message_logger.addHandler(ch)


        # set up logger for the events which we'd also expect to be logged by an observing proxy (file only)
        if args.log_only:
            formatter = logging.Formatter('{%(message)s}')
        else:
            formatter = logging.Formatter('{"TimeGenerated": "%(asctime)s", %(message)s}')

        self.event_logger = logging.getLogger('events')

        self.event_logger.setLevel(logging.DEBUG)

        eh = ConcurrentRotatingFileHandler('beaconing_simulation_events.log')
        eh.setFormatter(formatter)
        self.event_logger.addHandler(eh)


        self.ABSENCE_START: int         = 0
        self.COMMAND_RATIO: float       = 0.0
        self.EXFIL_START: int           = 0
        self.HOSTNAME: str              = socket.gethostname()
        self.USER: str                  = getlogin()  # TODO domain? upn?
        self.USER_ACTIVITY_IPS: dict    = {}
        self.USER_ACTIVITY_DOMAINS:list = [
            'amazon.com', 'cnn.com', 'github.com', 'google.com', 'instagram.com',
            'justbean.co', 'office.com', 'reddit.com', 'reuters.com', 'theuselessweb.com', 
            'tiktok.com', 'x.com', 'youtube.com', '9gag.com'
        ]

        self.absent: bool               = False
        self.args                       = args
        self.beaconing_uri: str         = 'ping'
        self.command_uri: str           = 'command'
        self.destination_domain: str    = ''
        self.destination_ip: str        = ''
        self.destination_ip_list: list  = []
        self.done: bool                 = False
        self.exfil_uri: str             = 'exfil'
        self.fake_timestamp: datetime   = datetime.now(timezone.utc) if args.start_time == 0 else datetime.fromtimestamp(args.start_time) # format is strftime('%m/%d/%Y %H:%M:%S.%.3f %p')
        self.reduction_count: int       = 0
        self.reduction_time:  int       = 0
        self.response                   = None


        print('resolving hostnames and ips... starting in a second...')
        for i in self.USER_ACTIVITY_DOMAINS:
            try:
                self.USER_ACTIVITY_IPS[i] = list({addr[-1][0] for addr in socket.getaddrinfo(i, 0, 0, 0, 0)})[0]  # always takes the first ip, even if multiple were returned
            except Exception:
                self.USER_ACTIVITY_IPS[i] = 'N/A'

        if args.destination.replace('.', '').isdigit():
            # ip was specified as destination
            self.destination_ip = self.args.destination

            try:
                self.destination_domain = socket.gethostbyaddr(self.args.destination)[0]
            except Exception:
                self.destination_domain = 'N/A'
        else:
            # domain was specified as destination
            self.destination_domain = self.args.destination

            try:
                self.destination_ip_list = list({addr[-1][0] for addr in socket.getaddrinfo(self.args.destination, 0, 0, 0, 0)})
            except Exception:
                self.destination_ip_list = ['N/A']
            self.destination_ip = self.destination_ip_list[0]  # always takes the first ip, even if multiple were returned


        self.message_logger.info(f'starting simulation...')

        if args.max_requests < 100:
            self.message_logger.info(f'max_requests was set to {self.args.max_requests}. it was automatically increased to 100.')
            self.args.max_requests = 100

        if args.jitter < 0:
            self.args.jitter = 0

        self.message_logger.info(f'will dispatch {self.args.max_requests} requests towards "{self.args.destination}" with an interval of {self.args.interval} seconds and {self.args.jitter}% jitter before ending the simulation.')
        self.message_logger.info(f'{"" if not self.args.no_noise else "no"} background noise as users would generate it will be simulated.')

        if not args.no_c2:
            if args.active_c2_ratio > 0.0:
                self.COMMAND_RATIO = self.args.active_c2_ratio
            elif args.active_c2_ratio <= 0.0:
                self.COMMAND_RATIO = random.uniform(0.1, 3.0)
            if args.active_c2_ratio > 50.0:
                self.COMMAND_RATIO = 10.0  # don't accept unreasonable large values

            self.message_logger.info(f'{self.COMMAND_RATIO}% of requests will simulate active usage of the c2 channel.')

        if args.absence > 0:
            self.ABSENCE_START = random.randint(int(self.args.max_requests*0.4), int(self.args.max_requests*0.8))  # start absence interval after x requests
            self.message_logger.info(f'{self.args.absence} minutes of absence (no beacons due to the device being offline/asleep/...) will be simulated after {self.ABSENCE_START} requests.')

        if not args.no_exfil:
            self.EXFIL_START = random.randint(int(self.args.max_requests*0.8)+1, self.args.max_requests)  # start exfiltration simulation after x requests. always after absence
            self.message_logger.info(f'data exfiltration will be simulated after {self.EXFIL_START} requests. {"data chunking will be used for exfiltration." if self.args.exfil_chunking != "NONE" else ""}')

        if args.log_only:
            self.message_logger.info(f'simulation will run in log-only mode. no actual requests will be dispatched.')
        else:
            self.message_logger.info(f'simulation will run at least {round((self.args.interval/60)*self.args.max_requests + self.args.absence, 2)} minutes.')
            # TODO do a check whether the destination is reachable


    @abc.abstractmethod
    def clean_up(self, **kwargs):
        """
        execute any code needed to clean up for the specific beacon type. e.g. terminate connections

        Args:
            needs to receive kwargs as required for the type of beacon
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def sleep(self):
        """
        roll jitter and let the beacon sleep for the interval plus jitter
        """
        jitter = random.uniform(-1.0*(self.args.interval/100)*self.args.jitter, 1.0*(self.args.interval/100)*self.args.jitter)
        jitter = 0 if (jitter < 0 and -jitter > self.args.interval) else jitter  # can't sleep negative time

        if self.args.log_only:
            self.fake_timestamp += timedelta(seconds=self.args.interval + jitter)

            # sleep additional time, if temporary throttling is active
            if self.reduction_count > 0:
                self.fake_timestamp += timedelta(seconds=self.reduction_time)
                self.reduction_count -= 1
        else:
            time.sleep(self.args.interval + jitter)

            # sleep additional time, if temporary throttling is active
            if self.reduction_count > 0:
                time.sleep(self.reduction_time)
                self.reduction_count -= 1


    def data_jitter(self):
        """
        return a random value to add or substract from sent data as jitter (currently somewhat hard-coded instead of percentual)
        """
        return random.randint(-200, 400)



    @abc.abstractmethod
    def write_log_event(self, **kwargs):
        """
        write the results of the current http(s) beacon to the log file

        Args:
            needs to receive kwargs as required for the type of beacon
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def noise_log_only(self):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def c2_iteration(self):
        """
        one beaconing iteration of the simulation with active c2 communication
        one iteration consists of multiple requests immitating how commands and results go back and forth for a while
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def exfil_iteration(self):
        """
        one beaconing iteration of the simulation with data exfiltration
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def normal_iteration(self):
        """
        one normal beaconing iteration of the simulation
        """
        raise NotImplementedError('Method must be implemented in child classes')


    @abc.abstractmethod
    def noise(self):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        raise NotImplementedError('Method must be implemented in child classes')
