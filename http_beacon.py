import random
import requests
import string
import urllib3

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # we don't care about ssl warnings as we're not exchanging any sensitive data





class HttpBeacon(Beacon):
    def __init__(self, args):
        super().__init__(args)


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


    def write_log_event(self, uri: str, sent_bytes: int, received_bytes: int):
        fake_time_generated = f'"TimeGenerated": "{self.fake_timestamp}", '

        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destination_domain}", \
            "DestinationIP": "{self.destination_ip if self.args.static_ip else random.choice(self.destination_ip_list)}", \
            "RequestMethods": "{self.args.request_method}", \
            "Protocol": "{self.args.protocol}", \
            "RequestURL": "{self.args.protocol.lower()}://{self.args.destination}/{uri}", \
            "SentBytes": {sent_bytes}, \
            "ReceivedBytes": {received_bytes}'''.replace('    ', ''))


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.write_log_event(self.beaconing_uri, 210 + random.randint(-200, 250), random.randint(400, 15000))

        # send fast beacons for a while indicating the command is running
        for i in range(random.randint(10, 400)):  # 10 -> 1-4 seconds runtime, 400 -> 40-160 seconds runtime with the defined fake sleep
            self.write_log_event(self.command_uri, 210 + random.randint(-200, 250), 360 + random.randint(-200, 250))
            self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        # command done, return execution results
        exfil_size = random.randint(1000, 15000000)

        if self.args.exfil_chunking != 'NONE' and exfil_size > 1000000:
            for i in range(int(exfil_size/1000000)):  # static 1MB chunks
                if self.args.exfil_chunking == 'URI':
                    self.write_log_event(''.join(random.choices(string.ascii_letters + string.digits, k=16)), 1000000, 360 + random.randint(-200, 250))
                else:
                    self.write_log_event(self.exfil_uri, 1000000, 360 + random.randint(-200, 250))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/MB
        else:
            self.write_log_event(self.exfil_uri, exfil_size, 550 + random.randint(-100, 450))
            self.fake_timestamp += timedelta(seconds=exfil_size/1000000)  # 1s/MB

        self.fake_timestamp += timedelta(seconds=random.randint(20, 300))  # operator is working on results and sending the next command


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        exfil_duration = random.randint(30, 600)
        exfil_size     = random.randint(10000000, 1000000000)

        self.write_log_event(self.beaconing_uri, 210 + random.randint(-200, 250), random.randint(400, 15000))  # receiving exfil command
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))

        if self.args.exfil_chunking != 'NONE':
            for i in range(int(exfil_size/1000000)):  # static 1MB chunks
                if self.args.exfil_chunking == 'URI':
                    self.write_log_event(''.join(random.choices(string.ascii_letters + string.digits, k=16)), 1000000, 360 + random.randint(-200, 250))
                else:
                    self.write_log_event(self.exfil_uri, 1000000, 360 + random.randint(-200, 250))
                self.fake_timestamp += timedelta(seconds=1)  # 1s/MB
        else:
            self.write_log_event(self.exfil_uri, exfil_size, 550 + random.randint(-100, 450))
            self.fake_timestamp += timedelta(seconds=exfil_size/1000000)  # 1s/MB


    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.write_log_event(self.beaconing_uri, 210 + random.randint(-200, 250), 360 + random.randint(-200, 250))
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


    def c2_iteration(self):
        """
        one beaconing iteration of the simulation with active c2 communication
        one iteration consists of multiple requests immitating how commands and results go back and forth for a while
        """
        for i in range(random.randint(1, 10)):  # up to X commands at once
            if self.args.use_dynamic_urls:
                command_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                exfil_uri   = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

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
            exfil_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

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
            beaconing_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        if self.args.log_only:
            self.normal_iteration_log_only()
        else:
            try:
                # TODO check response code?
                if self.args.request_method == 'POST':
                    response = requests.post(
                        f'{self.args.protocol.lower()}://{self.args.destination}/{self.beaconing_uri}',
                        headers={
                            'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                            'accept': '*/*',
                            'cache-control': 'no-cache'
                        },
                        data={'agent_id': 'dummyvalue'},
                        verify=False
                    )

                    self.write_log_event(self.beaconing_uri, approximate_request_size(response.request), len(response.body))
                else:
                    response = requests.get(
                        f'{self.args.protocol.lower()}://{self.args.destination}/{self.beaconing_uri}',
                        headers={
                            'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                            'accept': '*/*',
                            'cache-control': 'no-cache'
                        },
                        params={'agent_id': 'dummyvalue'},
                        verify=False
                    )

                    self.write_log_event(self.beaconing_uri, approximate_request_size(response.request), len(response.body))
            except Exception as e:
                print('oh no :\'( ', e)


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
            "RequestMethods": "{self.args.request_method}", \
            "Protocol": "{self.args.protocol}", \
            "RequestURL": "https://{domain}/{random_uri}", \
            "SentBytes": {random.randint(150, 600)}, \
            "ReceivedBytes": {random.randint(150, 300000)}'''.replace('    ', ''))
        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


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
                'cache-control': 'no-cache'
            },
            verify=False
        )

        self.event_logger.info(f'''\
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{domain}", \
            "DestinationIP": "{self.USER_ACTIVITY_IPS[domain]}", \
            "RequestMethods": "{self.args.request_method}", \
            "Protocol": "{self.args.protocol}", \
            "RequestURL": "https://{domain}/{random_uri}", \
            "SentBytes": {self.approximate_request_size(response.request)}, \
            "ReceivedBytes": {len(response.body)}'''.replace('    ', ''))
