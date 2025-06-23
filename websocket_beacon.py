import random
import string

from base_beacon            import Beacon
from concurrent_log_handler import ConcurrentRotatingFileHandler
from datetime               import datetime, timedelta, timezone




class WebsocketBeacon(Beacon):
    def __init__(self, args):
        super().__init__(args)
