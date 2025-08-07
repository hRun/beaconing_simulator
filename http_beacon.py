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
        self.default_response_size = random.randint(200, 20000)  # default response size heavily depends on the maleable profile (e.g. whether it's configured to return a legitimate-looking web page, etc. or not)
        self.default_request_size  = random.randint(150, 8191)


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


    def write_log_event(self, uri: str, sent_bytes: int, received_bytes: int):
        fake_time_generated = f'"TimeGenerated": "{self.fake_timestamp}", '

        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destinations[self.last_destination]['domain']}", \
            "DestinationIP": "{self.destinations[self.last_destination]['ips'][0] if self.args.static_ip else random.choice(self.destinations[self.last_destination]['ips'])}", \
            "RequestMethod": "{self.args.request_method}", \
            "Protocol": "{self.args.protocol}", \
            "RequestURL": "{self.args.protocol.lower()}://{self.destinations[self.last_destination]['primary']}/{uri}", \
            "SentBytes": {int(sent_bytes)}, \
            "ReceivedBytes": {int(received_bytes)}'''.replace('    ', ''))


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        exfil_size = random.randint(5000, 30000)

        self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(3000, 10000))  # receiving command
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        # optional: send faster beacons for a while indicating to the operator that the command is running
        # for i in range(random.randint(10, 120)):  # 2-120 seconds command runtime with the defined fake sleep
        #     self.write_log_event(self.command_uri, self.jitter_data(self.default_request_size), self.jitter_data(self.default_response_size))
        #     self.fake_timestamp += timedelta(milliseconds=random.randint(200, 1000))

        if self.chunk_size > 0 and exfil_size > self.chunk_size:
            for i in range(int(exfil_size/self.chunk_size)):
                if self.args.request_method == 'GET':
                    self.write_log_event(f'{self.command_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=16))}', self.chunk_size, self.jitter_data(self.default_response_size))  # during a real beacon the uri would have a length close to the request size
                else:
                    self.write_log_event(self.command_uri, self.chunk_size, self.jitter_data(self.default_response_size))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/chunk
        else:
            self.write_log_event(self.command_uri, exfil_size, self.jitter_data(550))
            self.fake_timestamp += timedelta(seconds=exfil_size/512000)  # 1s/512kb

        self.fake_timestamp += timedelta(seconds=random.randint(20, 300))  # operator is working on results and sending the next command


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        exfil_duration = random.randint(30, 600)
        exfil_size     = random.randint(100000, 1000000) if self.args.request_method == 'GET' else random.randint(1000000, 10000000)

        self.write_log_event(self.beaconing_uri, self.jitter_data(self.default_request_size), self.default_response_size + random.randint(3000, 10000))  # receiving exfil command
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        if self.chunk_size > 0 and exfil_size > self.chunk_size:
            for i in range(int(exfil_size/self.chunk_size)):
                if self.args.request_method == 'GET':
                    self.write_log_event(f'{self.exfil_uri}&__payload={''.join(random.choices(string.ascii_letters + string.digits, k=16))}', self.chunk_size, self.jitter_data(self.default_response_size))  # during a real beacon the uri would have a length close to the request size
                else:
                    self.write_log_event(self.exfil_uri, self.chunk_size, self.jitter_data(self.default_response_size))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/chunk
        else:
            self.write_log_event(self.exfil_uri, exfil_size, self.jitter_data(550))
            self.fake_timestamp += timedelta(seconds=exfil_size/512000)  # 1s/512kb


    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
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
                        f'{self.args.protocol.lower()}://{self.destinations[self.last_destination]['primary']}/{self.beaconing_uri}',
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
                        f'{self.args.protocol.lower()}://{self.destinations[self.last_destination]['primary']}/{self.beaconing_uri}',
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
                        f'{self.args.protocol.lower()}://{self.destinations[self.last_destination]['primary']}/{self.beaconing_uri}',
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
