import random
import requests
import string
import urllib3

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # we don't care about ssl warnings as we're not exchanging any sensitive data





class SocksBeacon(Beacon):
    """
    loosely based on https://sliver.sh/docs?name=HTTPS+C2, https://sliver.sh/docs?name=Reverse+SOCKS and https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.4.9.profile
    """


    def __init__(self, args):
        super().__init__(args)
        self.default_response_size = random.randint(200, 7000)  # default response size heavily depends on the maleable profile (e.g. whether it's configured to return a legitimate-looking web page, etc. or not)
        self.default_request_size  = random.randint(400, 750)


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


    def write_log_event(self, uri: str, sent_bytes: int, received_bytes: int, request_method: str = 'GET'):
        fake_time_generated = f'"TimeGenerated": "{self.fake_timestamp}", '

        self.event_logger.info(f'''\
            {fake_time_generated if self.args.log_only else ""} \
            "SourceUserName": "{self.USER}", \
            "DeviceName": "{self.HOSTNAME}", \
            "DestinationHostName": "{self.destinations[self.last_destination]['domain']}", \
            "DestinationIP": "{self.destinations[self.last_destination]['ips'][0] if self.args.static_ip else random.choice(self.destinations[self.last_destination]['ips'])}", \
            "RequestMethod": "{request_method}", \
            "Protocol": "HTTP", \
            "RequestURL": "http://{self.destinations[self.last_destination]['primary']}/{uri}", \
            "SentBytes": {int(sent_bytes)}, \
            "ReceivedBytes": {int(received_bytes)}'''.replace('    ', ''))


    def c2_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        # roll command result size & chunk number
        exfil_size = random.randint(5000, 15000000)
        chunks     = int(exfil_size/460800) if int(exfil_size/460800) > 0 else random.randint(3, 10)

        for i in range(chunks):
            if random.randint(1, 2) == 1:
                self.write_log_event(self.beaconing_uri, self.default_request_size, self.default_response_size + self.data_jitter(), 'GET')  # continuation of "empty" requests

            self.write_log_event(f'{self.command_uri}?{''.join(random.choices(string.ascii_letters + string.digits, k=6))}={''.join(random.choices(string.ascii_letters + string.digits, k=24))}', exfil_size/chunks, self.default_response_size + self.data_jitter(), 'POST')
            self.write_log_event(self.command_uri, self.default_request_size*random.randint(5, 10) + self.data_jitter(), self.default_response_size + self.data_jitter(), 'GET')

            if random.randint(1, 2) == 1:
                self.write_log_event(self.beaconing_uri, self.default_request_size, self.default_response_size + self.data_jitter(), 'GET')  # continuation of "empty" requests
            self.write_log_event(self.beaconing_uri, self.default_request_size, self.default_response_size + self.data_jitter(), 'GET')  # continuation of "empty" requests

            self.fake_timestamp += timedelta(milliseconds=random.randint(25, 100))  # seems like appropriate values. can be changed though

        self.fake_timestamp += timedelta(milliseconds=random.randint(100, 400))  # seems like appropriate values. can be changed though


    def exfil_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        seems equivalent to c2 traffic in case of socks usage
        """
        self.command_uri = self.exfil_uri
        self.c2_iteration_log_only()


    def normal_iteration_log_only(self):
        """
        one iteration of the simulation where events are only logged, no actual request is dispatched
        """
        self.write_log_event(self.beaconing_uri, self.default_request_size + self.data_jitter(), self.default_response_size + self.data_jitter(), 'GET')
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
        for i in range(random.randint(1, 5)):  # up to X commands at once
            if self.args.use_dynamic_urls:
                self.command_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                self.exfil_uri   = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

            if self.args.log_only:
                self.c2_iteration_log_only()
            else:
                try:
                    pass  # TODO requires a server-side
                except Exception:
                    pass

        self.next_destination()


    def exfil_iteration(self):
        """
        one beaconing iteration of the simulation with data exfiltration
        """
        if self.args.use_dynamic_urls:
            self.exfil_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        if self.args.log_only:
            self.exfil_iteration_log_only()
        else:
            try:
                pass  # TODO requires a server-side
            except Exception:
                pass

        self.next_destination()


    def normal_iteration(self):
        """
        one normal beaconing iteration of the simulation
        """
        if self.args.use_dynamic_urls:
            self.beaconing_uri = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        if self.args.log_only:
            self.normal_iteration_log_only()
        else:  # TODO requires a server-side
            try:
                # TODO check response code?
                response = requests.get(
                    f'http://{self.args.destination}/{self.beaconing_uri}',
                    headers={
                        'user-agent': 'Beaconing Simulation Script for Threat Hunting and Attack Simulation',
                        'accept': '*/*',
                        # 'cache-control': 'no-cache'
                    },
                    params={'agent_id': 'dummyvalue'},
                    verify=False
                )

                self.write_log_event(self.beaconing_uri, self.approximate_request_size(response.request), len(response.text), 'GET')
            except Exception as e:
                print('oh no :\'( ', e)

        self.next_destination()


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
import socket
import threading
import time
import socks

# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 1080  # SOCKS port

def handle_client(client_socket):
    try:
        print("Client connected.")
        while True:
            # Send a message every 10 seconds
            message = "Hello from server!\n"
            client_socket.sendall(message.encode())
            print("Sent message to client.")
            time.sleep(10)
    except (ConnectionResetError, BrokenPipeError):
        print("Client disconnected.")
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    print(f"Listening for incoming SOCKS connections on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client_sock, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_sock,))
        client_thread.daemon = True
        client_thread.start()

# Client code to connect via SOCKS server and send requests
def connect_through_socks(proxy_host, proxy_port, target_host, target_port):
    # Setup a SOCKS5 proxy connection
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
    s.connect((target_host, target_port))
    print(f"Connected to {target_host}:{target_port} through SOCKS proxy at {proxy_host}:{proxy_port}")
    try:
        while True:
            # Send a request every 10 seconds
            s.sendall(b"GET / HTTP/1.1\r
Host: example.com\r
\r
")
            print("Request sent through SOCKS proxy.")
            time.sleep(10)
    except (ConnectionResetError, BrokenPipeError):
        print("Connection closed.")
    finally:
        s.close()

# To run the server:
# start_server()

# To run the client:
# connect_through_socks('127.0.0.1', 1080, 'target.server.com', 80)
"""
