import asyncio
import random
import string
import websockets

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone




# TODO
class WebsocketBeacon(Beacon):
    def __init__(self, args):
        super().__init__(args)


    def write_log_event(self, **kwargs):
        """
        write the results of the current http(s) beacon to the log file

        Args:
            needs to receive kwargs as required for the type of beacon
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def noise_log_only(self):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def c2_iteration(self):
        """
        one beaconing iteration of the simulation with active c2 communication
        one iteration consists of multiple requests immitating how commands and results go back and forth for a while
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def exfil_iteration(self):
        """
        one beaconing iteration of the simulation with data exfiltration
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def normal_iteration(self):
        """
        one normal beaconing iteration of the simulation
        """
        raise NotImplementedError('Method must be implemented in child classes')


    def noise(self):
        """
        make one or multiple requests simulating normal user activity while a beacon is going
        """
        raise NotImplementedError('Method must be implemented in child classes')




"""
import asyncio
import websockets
import json


async def send_message(url):
    async with websockets.connect(url) as websocket:
        await websocket.send(
            json.dumps(
                {
                    'dummy_key': 'dummy_value'
                }
            )
        )
        # await asyncio.sleep(30)


async def create_ws_connection(url):
    await send_periodic_messages(url)


asyncio.run(create_ws_connection('wss://echo.websocket.org'))
"""


"""
maybe better?!

https://websockets.readthedocs.io/en/stable/index.html
"""


"""
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

            # when closing
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

        send
            -> no events at all
"""


# https://sliver.sh/docs?name=HTTPS+C2
# https://docs.mythic-c2.net/operational-pieces/c2-profiles/dynamichttp
