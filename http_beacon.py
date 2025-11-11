import random
import requests
import string
import urllib3

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # we don't care about ssl warnings as we're not exchanging any sensitive data





class HttpBeacon(Beacon):
    """
    loosely based on https://sliver.sh/docs?name=HTTPS+C2 and https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.4.9.profile
    """


    def __init__(self, args):
        super().__init__(args)
        self.default_request_size  = random.randint(150, 8191)

        if self.args.response_size == 'LARGE':
            self.default_response_size = random.randint(20000, 200000)  # maleable profile which e.g. returna a legitimate-looking web page
        elif self.args.response_size == 'RANDOM':
            self.default_response_size = random.randint(200, 100000)  # maleable profile which returns random data in addition to the beacon data
        else:
            self.default_response_size = random.randint(700, 4000)  # maleable profile which returns the bare minimum data

        self.message_logger.info(f'rolled a default http request size of {self.default_request_size} bytes and a default http response size of {self.default_response_size} bytes. will apply {self.args.data_jitter}% jitter. jitter will {"not" if self.args.cap_data_jitter in [None, ""] else ""} be capped if provided limits are reached.')

        if self.args.protocol == 'HTTPSxSOCKS':
            session_amount          = random.randint(1, self.args.max_socks_sessions) if self.args.max_socks_sessions >=1 and self.args.max_socks_sessions < self.args.max_requests-11 else random.randint(1, 4)  # roll exact number of socks sessions to simulate. don't allow invalid values
            self.SOCKS_REQUESTS     = [random.randint(10, self.args.max_requests-1) for i in range(1, session_amount+1)]  # pre-roll the requests during which socks sessions should start
            self.MAX_SOCKS_DURATION = random.randint(2, 20)  # minutes
            self.args.protocol      = 'HTTPS'
            self.message_logger.info(f'{session_amount} instances of sudden SOCKS traffic, up to {self.MAX_SOCKS_DURATION} minutes each, will be simulated. as if the device was used as reverse proxy by the c2 server to run code (e.g. enumeration).')


    def clean_up(self, **kwargs):
        pass  # no clean up required


    def approximate_request_size(self, request) -> int:
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
            size += request.body if 'body' in request else 0
        except Exception:
            pass
        return size


    def write_log_event(self, uri: str, sent_bytes: int, received_bytes: int, request_method: str = ''):
        fake_time_generated = f'"TimeGenerated": "{self.fake_timestamp}", '

        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destinations[self.destination_index]['domain']}", \
            "DestinationIP": "{self.destinations[self.destination_index]['ips'][0] if self.args.static_ip else random.choice(self.destinations[self.destination_index]['ips'])}", \
            "RequestMethod": "{request_method if request_method != '' else self.args.request_method}", \
            "Protocol": "{self.args.protocol}", \
            "RequestURL": "{self.args.protocol.lower()}://{self.destinations[self.destination_index]['primary']}/{uri}", \
            "SentBytes": {int(sent_bytes)}, \
            "ReceivedBytes": {int(received_bytes)}'''.replace('    ', ''))


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        exfil_size = random.randint(500000, 2000000) if self.discovery_phase is True else random.randint(5000, 30000)  # assume a command which returns a lot of output during first c2 usage (e.g. an operator doing enumeration vs. just execution later on)

        if self.args.request_method == 'MIXED':
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(600, 500000), 'GET')  # receiving command (eventually including tooling)
        else:
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(600, 500000))  # receiving command (eventually including tooling)
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        # optional: send faster beacons for a while indicating to the operator that the command is running
        # for i in range(random.randint(10, 120)):  # 2-120 seconds command runtime with the defined fake sleep
        #     self.write_log_event(self.command_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size))
        #     self.fake_timestamp += timedelta(milliseconds=random.randint(200, 1000))

        if self.chunk_size > 0 and exfil_size > self.chunk_size:
            for i in range(int(exfil_size/self.chunk_size)):
                if self.args.request_method == 'GET':
                    self.write_log_event(f'{self.command_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=16))}', self.chunk_size, self.jitter_data(self.default_response_size))  # during a real beacon the uri would have a length close to the request size
                elif self.args.request_method == 'MIXED':
                    self.write_log_event(self.command_uri, self.chunk_size, self.jitter_data(self.default_response_size), 'POST')
                else:
                    self.write_log_event(self.command_uri, self.chunk_size, self.jitter_data(self.default_response_size))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/chunk
        else:
            if self.args.request_method == 'MIXED':
                self.write_log_event(self.command_uri, exfil_size, self.jitter_data(self.default_response_size), 'POST')
            else:
                self.write_log_event(self.command_uri, exfil_size, self.jitter_data(self.default_response_size))
            self.fake_timestamp += timedelta(seconds=exfil_size/512000)  # 1s/512kb

        self.fake_timestamp += timedelta(seconds=random.randint(20, 300))  # operator is working on results and sending the next command. TODO this should be removed, instead do a bunch of normal requests


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        exfil_duration = random.randint(30, 600)
        exfil_size     = random.randint(500000, 2000000) if self.args.request_method == 'GET' else random.randint(10000000, 50000000)

        if self.args.request_method == 'MIXED':
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(600, 500000), 'GET')  # receiving exfil command (eventually including tooling)
        else:
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(600, 500000))  # receiving exfil command (eventually including tooling)
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        if self.chunk_size > 0 and exfil_size > self.chunk_size:
            for i in range(int(exfil_size/self.chunk_size)):
                if self.args.request_method == 'GET':
                    self.write_log_event(f'{self.exfil_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=16))}', self.chunk_size, self.jitter_data(self.default_response_size))  # during a real beacon the uri would have a length close to the request size
                elif self.args.request_method == 'MIXED':
                    self.write_log_event(self.exfil_uri, self.chunk_size, self.jitter_data(self.default_response_size), 'POST')
                else:
                    self.write_log_event(self.exfil_uri, self.chunk_size, self.jitter_data(self.default_response_size))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/chunk
        else:
            if self.args.request_method == 'MIXED':
                self.write_log_event(self.exfil_uri, exfil_size, self.jitter_data(self.default_response_size), 'POST')
            else:
                self.write_log_event(self.exfil_uri, exfil_size, self.jitter_data(self.default_response_size))
            self.fake_timestamp += timedelta(seconds=exfil_size/512000)  # 1s/512kb


    def socks_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        socks_session_duration_tracker = 0  # seconds. used to determine when the socks session is supposed to end
        normal_checkin_tracker         = 0  # seconds. used to determine when normal beaconing check in requests need to be dispatched in the background in parallel to the socks traffic
        socks_session_duration         = random.randint(1, self.MAX_SOCKS_DURATION)*60

        self.message_logger.info(f'simulated socks session will last for approximately {int(socks_session_duration/60)} minutes.')

        # one normal checkin request which initializes the socks session (indicated by a lerger than normal response size)
        if self.args.request_method == 'MIXED':
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size)+random.randint(4000, 8000), 'GET')
        else:
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size)+random.randint(4000, 8000))
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though

        # run the socks session as long as rolled
        while socks_session_duration_tracker < socks_session_duration:
            # socks session ran as long as the usual beaconing interval. so a normal beaconing check in request must happen in the background. ignore time jitter for simplicity
            # TODO this could also happen in between the two socks packets. but considering the minimal time difference, this is probably not important for detection
            if normal_checkin_tracker >= self.args.interval:
                if self.args.request_method == 'MIXED':
                    self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size), 'GET')
                else:
                    self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size))
                normal_checkin_tracker = 0  # reset

            # socks session traffic
            # traffic size during socks sessions seems to be somewhat static based on slightly simplified real-world observations (in case of cs) for both request and response
            if self.args.request_method == 'MIXED':
                self.write_log_event(f'{self.proxy_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=24))}', random.randint(1000, 8000)*random.uniform(0.95, 1.07), random.randint(1000, 8000)*random.uniform(0.95, 1.07), 'POST')
                time_increase1       = random.randint(100, 200)
                self.fake_timestamp += timedelta(milliseconds=time_increase1)
                self.write_log_event(self.proxy_uri, random.randint(1000, 8000)*random.uniform(0.95, 1.07), random.randint(1000, 8000)*random.uniform(0.95, 1.07), 'GET')
            else:
                self.write_log_event(f'{self.proxy_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=24))}', random.randint(1000, 8000)*random.uniform(0.95, 1.07), random.randint(1000, 8000)*random.uniform(0.95, 1.07))
                time_increase1       = random.randint(100, 200)
                self.fake_timestamp += timedelta(milliseconds=time_increase1)
                self.write_log_event(self.proxy_uri, random.randint(1000, 8000)*random.uniform(0.95, 1.07), random.randint(1000, 8000)*random.uniform(0.95, 1.07))

            time_increase2                  = random.randint(100, 200)  # seems like appropriate values (ms). can be changed though
            socks_session_duration_tracker += (time_increase1+time_increase2)/1000
            normal_checkin_tracker         += (time_increase1+time_increase2)/1000
            self.fake_timestamp            += timedelta(milliseconds=time_increase2)

        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        if self.args.request_method == 'MIXED':
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size), 'GET')
        else:
            self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size))
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


    def noise_log_only(self, domain: str):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        random_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        random_uri = random_uri if random.randint(0, 100) < 20 else ''  # browse a "legitimate random" subpage in X% of cases, else just go to the home page

        self.event_logger.info(f'''\
            "TimeGenerated": "{self.fake_timestamp}", \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{domain}", \
            "DestinationIP": "{self.USER_ACTIVITY_IPS[domain]}", \
            "RequestMethod": "GET", \
            "Protocol": "HTTPS", \
            "RequestURL": "https://{domain}/{random_uri}", \
            "SentBytes": {random.randint(150, 600)}, \
            "ReceivedBytes": {random.randint(150, 300000)}'''.replace('    ', ''))
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


    def c2_iteration(self):
        """
        one beaconing iteration of the simulation with active c2 communication
        one iteration consists of multiple requests immitating how commands and results go back and forth for a while
        """
        for i in range(random.randint(1, 4)):  # up to X commands at once
            if self.args.use_dynamic_urls:
                self.command_uri = f'{''.join(random.choices(string.ascii_letters + string.digits, k=16))}?__c2'

            if self.args.log_only:
                self.c2_iteration_log_only()
            else:
                try:
                    pass  # TODO requires a server-side
                except Exception:
                    pass

            if self.discovery_phase is True:
                break  # only simulate 1 command during first c2 usage


    def exfil_iteration(self):
        """
        one beaconing iteration of the simulation with data exfiltration
        """
        if self.args.use_dynamic_urls:
            self.exfil_uri = f'{''.join(random.choices(string.ascii_letters + string.digits, k=16))}?__exfil'

        if self.args.log_only:
            self.exfil_iteration_log_only()
        else:
            try:
                pass  # TODO requires a server-side
            except Exception:
                pass


    def socks_iteration(self):
        """
        one beaconing iteration where the device is used as reverse proxy by the c2 server for running code (e.g. enumeration)
        """
        if self.args.use_dynamic_urls:
            self.proxy_uri = f'{''.join(random.choices(string.ascii_letters + string.digits, k=16))}?__proxy'

        if self.args.log_only:
            self.socks_iteration_log_only()
        else:
            try:
                pass  # TODO requires a server-side
            except Exception:
                pass


    def normal_iteration(self):
        """
        one normal beaconing iteration of the simulation
        """
        if self.args.use_dynamic_urls:
            self.beaconing_uri = f'{''.join(random.choices(string.ascii_letters + string.digits, k=16))}?__ping'

        if self.args.log_only:
            self.normal_iteration_log_only()
        else:  # TODO requires a server-side
            try:
                # TODO check response code?
                if self.args.request_method == 'POST':
                    response = requests.post(
                        f'{self.args.protocol.lower()}://{self.destinations[self.destination_index]['primary']}/{self.beaconing_uri}',
                        headers={
                            'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                            'accept': '*/*',
                            # 'cache-control': 'no-cache'
                        },
                        data={'agent_id': 'dummyvalue'},
                        verify=False
                    )

                    self.write_log_event(self.beaconing_uri, self.approximate_request_size(response.request), len(response.text))
                elif self.args.request_method == 'PUT':
                    response = requests.put(
                        f'{self.args.protocol.lower()}://{self.destinations[self.destination_index]['primary']}/{self.beaconing_uri}',
                        headers={
                            'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                            'accept': '*/*',
                            # 'cache-control': 'no-cache'
                        },
                        params={'agent_id': 'dummyvalue'},
                        data={'agent_id': 'dummyvalue'},
                        verify=False
                    )
                else:
                    # default to GET
                    response = requests.get(
                        f'{self.args.protocol.lower()}://{self.destinations[self.destination_index]['primary']}/{self.beaconing_uri}',
                        headers={
                            'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                            'accept': '*/*',
                            # 'cache-control': 'no-cache'
                        },
                        params={'agent_id': 'dummyvalue'},
                        verify=False
                    )

                    self.write_log_event(self.beaconing_uri, self.approximate_request_size(response.request), len(response.text))
            except Exception as e:
                print('oh no :\'( ', e)


    def noise(self):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        random_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        random_uri = random_uri if random.randint(0, 100) < 20 else ''  # browse a "legitimate random" subpage in X% of cases, else just go to the home page

        response = requests.get(
            f'https://{domain}/{random_uri}',
            headers={
                'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                'accept': '*/*',
                # 'cache-control': 'no-cache'
            },
            verify=False
        )

        self.event_logger.info(f'''\
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{domain}", \
            "DestinationIP": "{self.USER_ACTIVITY_IPS[domain]}", \
            "RequestMethod": "GET", \
            "Protocol": "HTTPS", \
            "RequestURL": "https://{domain}/{random_uri}", \
            "SentBytes": {self.approximate_request_size(response.request)}, \
            "ReceivedBytes": {len(response.text)}'''.replace('    ', ''))
