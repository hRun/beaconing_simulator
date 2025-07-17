import asyncio
import random
import string
import websockets

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone




# TODO
class WebSocketClient:
    def __init__(self, url):
        self.connection = None
        self.url        = url

    async def connect(self):
        self.connection = await websockets.connect(self.url)

    async def send(self, message):
        if self.connection is None:
            await self.connect()
        await self.connection.send(message)

    async def receive(self):
        if self.connection is None:
            await self.connect()
        return await self.connection.recv()

    async def close(self):
        if self.connection:
            await self.connection.close()
            self.connection = None




class WebsocketBeacon(Beacon):
    def __init__(self, args):
        super().__init__(args)
        self.default_response_size = random.randint(200, 7000)  # default response size heavily depends on the maleable profile (e.g. whether it's configured to return a legitimate-looking web page, etc. or not)
        self.default_request_size  = random.randint(400, 750)
        self.total_bytes_sent      = 0
        self.total_bytes_received  = 0

        self.write_log_event(self.beaconing_uri, 270 + self.data_jitter(), 279 + self.data_jitter(), 'HTTPS', 'GET')

        if not self.args.log_only:
            try:
                pass  # TODO requires a server-side
                """
                # asyncio.run(run_ws_beacon(f'wss://{self.args.destination}/{self.beaconing_uri}'))
                self.ws_connection = WebSocketClient(f'wss://{self.args.destination}/{self.beaconing_uri}')
                await ws_client.connect()
                """
            except Exception:
                pass


    def clean_up(self, **kwargs):
        self.write_log_event(self.beaconing_uri, self.total_bytes_sent, self.total_bytes_received)

        if not self.args.log_only:
            try:
                # await self.ws_client.close()
                pass  # TODO requires a server-side
            except Exception:
                pass


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


    def write_log_event(self, uri: str, sent_bytes: int, received_bytes: int, protocol: str = 'WEBSOCKET_SSL', request_method: str = 'NA'):
        fake_time_generated = f'"TimeGenerated": "{self.fake_timestamp}", '

        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destination_domain}", \
            "DestinationIP": "{self.destination_ip if self.args.static_ip else random.choice(self.destination_ip_list)}", \
            "RequestMethod": "{request_method}", \
            "Protocol": "{protocol}", \
            "RequestURL": "{'wss' if protocol == 'WEBSOCKET_SSL' else protocol.lower()}://{self.args.destination}/{uri}", \
            "SentBytes": {int(sent_bytes)}, \
            "ReceivedBytes": {int(received_bytes)}'''.replace('    ', ''))


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.total_bytes_sent     += random.randint(400, 750)
        self.total_bytes_received += random.randint(5000, 15000000)
        self.fake_timestamp       += timedelta(seconds=random.randint(10, 120))  # seems like appropriate values. can be changed though


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.total_bytes_sent     += random.randint(400, 750)
        self.total_bytes_received += random.randint(10000000, 1000000000)
        self.fake_timestamp       += timedelta(seconds=random.randint(30, 600))  # seems like appropriate values. can be changed though



    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.total_bytes_sent     += self.default_request_size + self.data_jitter()
        self.total_bytes_received += self.default_response_size + self.data_jitter()
        self.fake_timestamp       += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


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
        for i in range(random.randint(1, 5)):  # up to X commands at once
            """if self.args.use_dynamic_urls:
                self.command_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                self.exfil_uri   = ''.join(random.choices(string.ascii_letters + string.digits, k=16))"""

            if self.args.log_only:
                self.c2_iteration_log_only()
            else:
                try:
                    # message = "Dummy Message"
                    # await self.ws_client.send(message)
                    # self.total_bytes_sent += len(message)
                    # self.total_bytes_received = await ws_client.receive()
                    pass  # TODO requires a server-side
                except Exception:
                    pass


    def exfil_iteration(self):
        """
        one beaconing iteration of the simulation with data exfiltration
        """
        """if self.args.use_dynamic_urls:
            self.exfil_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))"""

        if self.args.log_only:
            self.exfil_iteration_log_only()
        else:
            try:
                # message = "Dummy Message"
                # await self.ws_client.send(message)
                # self.total_bytes_sent += len(message)
                # self.total_bytes_received = await ws_client.receive()
                pass  # TODO requires a server-side
            except Exception:
                pass


    def normal_iteration(self):
        """
        one normal beaconing iteration of the simulation
        """
        """if self.args.use_dynamic_urls:
            self.beaconing_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))"""

        if self.args.log_only:
            self.normal_iteration_log_only()
        else:
            try:
                # message = "Dummy Message"
                # await self.ws_client.send(message)
                # self.total_bytes_sent += len(message)
                # self.total_bytes_received = await ws_client.receive()
                pass  # TODO requires a server-side
            except Exception:
                pass


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




"""
working, simple ws code:

import asyncio
import websockets
import json


async def send_message(url):
    async with websockets.connect(url) as websocket:
        for i in range(10):
            await websocket.send(
                json.dumps(
                    {
                        'dummy_key': 'dummy_value'
                    }
                )
            )

            response = await websocket.recv()
            print(response)
            await asyncio.sleep(10)


async def create_ws_connection(url):
    await send_message(url)


asyncio.run(create_ws_connection('wss://echo.websocket.org'))


# alternative: https://websockets.readthedocs.io/en/stable/index.html


results from using echo.websocket.org:

client:
    connect
        # 101 return code
        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destination_domain}", \
            "DestinationIP": "{self.destination_ip if self.args.static_ip else random.choice(self.destination_ip_list)}", \
            "RequestMethods": "GET", \
            "Protocol": "HTTP(S)", \
            "RequestURL": "(wss://){self.args.destination}/{uri}", \
            "SentBytes": 270, \
            "ReceivedBytes": 279'''.replace('    ', ''))

    send
        -> no events at all

    close
        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destination_domain}", \
            "DestinationIP": "{self.destination_ip if self.args.static_ip else random.choice(self.destination_ip_list)}", \
            "RequestMethods": "NA", \
            "Protocol": "WEBSOCKET_SSL", \
            "RequestURL": "(wss://){self.args.destination}/{uri}", \
            "SentBytes": AGGREGATED_BYTES_OVER_ALL_REQUESTS, \
            "ReceivedBytes": AGGREGATED_BYTES_OVER_ALL_REQUESTS'''.replace('    ', ''))
"""
