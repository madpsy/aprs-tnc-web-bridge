#!/usr/bin/env python
import eventlet
# Monkey patch as early as possible
eventlet.monkey_patch()

import queue
import threading
import socket
import aprslib
import yaml
from datetime import datetime
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, disconnect
from collections import deque
import time
import os
import json  # For sending JSON over UDP
import serial  # Added for serial connections
import sys
import paho.mqtt.client as mqtt

# Create needed directories
os.makedirs("logs", exist_ok=True)
os.makedirs("config", exist_ok=True)

# Open the log file.
# (We delay reassigning sys.stdout/sys.stderr until after Socket.IO is available.)
log_file = open("logs/tnc.log", "a", buffering=1)  # "a" = append, buffering=1 (line-buffered)

# ------------------------------------------------------------------------------
#  LogTee: a file-like object that writes to the log file and also emits via websockets.
#  We use a global variable "socketio_instance" (set later) so that every call to write()
#  sends the message to the Socket.IO namespace '/logs'.
# ------------------------------------------------------------------------------
socketio_instance = None  # Will be set later in main() after Socket.IO is initialised.

class LogTee:
    def __init__(self, logfile, namespace='/logs'):
        self.logfile = logfile
        self.namespace = namespace

    def write(self, message):
        # Write to the log file
        self.logfile.write(message)
        self.logfile.flush()
        # If Socket.IO is available, emit the log message
        if socketio_instance is not None:
            try:
                socketio_instance.emit('log', {'msg': message}, namespace=self.namespace)
            except Exception as e:
                self.logfile.write(f"\n[Error emitting log via Socket.IO: {e}]\n")
                self.logfile.flush()

    def flush(self):
        self.logfile.flush()

# ------------------------------------------------------------------------------
#  Constants and Global Variables
# ------------------------------------------------------------------------------
KISS_FLAG = 0xC0
KISS_CMD_DATA = 0x00

# Target for sending JSON-encoded packets via UDP
UDP_TARGET = ("lora.link9.net", 1515)

# Default delay between sending frames to the TNC in milliseconds
DEFAULT_SEND_DELAY_MS = 10000  # 10s

# Global TNC connection reference for sending data
tnc_connection = None

# Globals for logging
no_log = False
filename = None

# Global for iGate callsign (used for sending to UDP)
igate_callsign = None

# Globals for connection tracking
connected_ip = None
active_sids = {}

# ### MQTT: Global references for MQTT
mqtt_host = "127.0.0.1"
mqtt_port = 1883
mqtt_tls = False
mqtt_user = ""
mqtt_pass = ""
mqtt_manager = None  # Will be set to an instance of MqttManager if needed

# ### MQTT-FORWARD: New global
mqtt_forward = False  # Will be set if the user enables mqtt_forward

# ### APRS-IS Globals
aprs_enabled = False
aprs_callsign = ""
aprs_host = "rotate.aprs2.net"
aprs_port = 14580
aprs_socket = None
aprs_lock = threading.Lock()  # To synchronise access to APRS socket

# Initialise Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

# Initialise SocketIO without passing the app initially.
socketio = SocketIO(async_mode='eventlet')  # Explicitly set eventlet as async mode

# Deque for storing the last 'r' packets (maxlen set in main)
packet_history = deque()

# Initialise settings
CONFIG_FILE = 'config/settings.yaml'
config_lock = threading.Lock()
config = {}

# ------------------------------------------------------------------------------
#  HTML page for the root
# ------------------------------------------------------------------------------
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>APRS TNC</title>
    <script>
        function initializeFrames() {
            fetch('/api/settings')
                .then(response => response.json())
                .then(data => {
                    const cs = data.my_callsign;
                    if (cs) {
                        const param = `?callsign=${encodeURIComponent(cs)}`;
                        document.getElementsByName('leftFrame')[0].src += param;
                        document.getElementsByName('rightFrame')[0].src += param;
                    }
                });
        }
    </script>
</head>
<frameset cols="65%,*" onload="initializeFrames()">
    <frame src="/static/map.html" name="leftFrame">
    <frame src="/static/messages.html" name="rightFrame">
</frameset>
</html>
"""

@app.route('/')
def index():
    return HTML_PAGE

# ------------------------------------------------------------------------------
#  API endpoint to serve the current log file via HTTP
# ------------------------------------------------------------------------------
@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        with open('logs/tnc.log', 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        return f"Error reading log file: {e}", 500

# ------------------------------------------------------------------------------
#                          SETTINGS MANAGEMENT
# ------------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    'connection_type': 'tcp',  # 'tcp', 'serial', or 'aprs-is'
    'host': '127.0.0.1',
    'port': 1234,
    'device': '/dev/ttyUSB0',
    'baud': 9600,
    'listen': '0.0.0.0:5001',
    'resume': 100,
    'no_log': False,
    'send': None,
    'debug': False,
    'delay': 1000,
    'mqtt_host': '127.0.0.1',
    'mqtt_port': 1883,
    'mqtt_tls': False,
    'mqtt_user': '',
    'mqtt_pass': '',
    'mqtt_forward': False,
    'my_callsign': None,
    'telemetry_interval': 120,
    'aprs_callsign': None,
    'aprs_host': 'rotate.aprs2.net',
    'aprs_port': 14580,
    'aprs_filter': 'm/100',
    'proxy_enabled': False,
    'proxy_port': 5002
}

def write_default_settings():
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(DEFAULT_SETTINGS, f)
    print(f"Default settings.yaml created. Restarting with default settings...")
    def restart():
        python = sys.executable
        os.execl(python, python, *sys.argv)
    threading.Thread(target=restart, daemon=True).start()

def load_settings():
    global config
    if not os.path.exists(CONFIG_FILE):
        write_default_settings()
    with open(CONFIG_FILE, 'r') as f:
        try:
            loaded_config = yaml.safe_load(f)
            if loaded_config is None:
                loaded_config = {}
        except yaml.YAMLError as e:
            print(f"Error loading {CONFIG_FILE}: {e}")
            exit(1)
    # Merge with defaults
    for key, value in DEFAULT_SETTINGS.items():
        if key not in loaded_config:
            loaded_config[key] = value
    config = loaded_config
    validate_settings()

def write_settings(new_settings):
    global config
    with config_lock:
        config.update(new_settings)
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(config, f)

def validate_settings():
    global config
    ct = config.get('connection_type')
    if ct not in ['tcp', 'serial', 'aprs-is']:
        print("Error: 'connection_type' must be 'tcp', 'serial', or 'aprs-is'.")
        exit(1)
    if ct == 'tcp':
        if not config.get('host') or not config.get('port'):
            print("Error: 'host' and 'port' must be set for TCP connection.")
            exit(1)
    elif ct == 'serial':
        if not config.get('device') or not config.get('baud'):
            print("Error: 'device' and 'baud' must be set for Serial connection.")
            exit(1)
    elif ct == 'aprs-is':
        if not config.get('aprs_callsign'):
            print("Error: 'aprs_callsign' must be set when 'connection_type' is 'aprs-is'.")
            exit(1)
    # Validate aprs_filter (basic validation)
    aprs_filter = config.get('aprs_filter', 'm/100')
    if not isinstance(aprs_filter, str) or not aprs_filter.startswith('m/'):
        print("Error: 'aprs_filter' must be a string starting with 'm/'.")
        exit(1)

# ------------------------------------------------------------------------------
#  API ENDPOINTS FOR SETTINGS
# ------------------------------------------------------------------------------
@app.route('/api/settings', methods=['GET', 'POST'])
def manage_settings():
    global config
    if request.method == 'GET':
        with config_lock:
            return jsonify(config), 200
    elif request.method == 'POST':
        new_settings = request.get_json()
        if not new_settings:
            return jsonify({"error": "No JSON body provided"}), 400
        # Update settings
        with config_lock:
            config.update(new_settings)
            # Validate updated settings
            try:
                validate_settings()
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            # Write to settings.yaml
            try:
                with open(CONFIG_FILE, 'w') as f:
                    yaml.dump(config, f)
            except Exception as e:
                return jsonify({"error": f"Failed to write settings: {e}"}), 500
        # Restart the programme to apply new settings
        def restart():
            time.sleep(1)  # Delay to ensure response is sent
            python = sys.executable
            os.execl(python, python, *sys.argv)
        threading.Thread(target=restart, daemon=True).start()
        return jsonify({"status": "Settings updated. Restarting..."}), 200

# ------------------------------------------------------------------------------
#                          TNC CONNECTION CLASS
# ------------------------------------------------------------------------------
class TNCConnection:
    """
    Abstracts the connection to the TNC, supporting both TCP and Serial connections.
    Provides unified sendall and recv methods.
    """
    def __init__(self, connection_type, **kwargs):
        self.connection_type = connection_type
        if connection_type == 'tcp':
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.settimeout(kwargs.get('timeout', 5))
            self.conn.connect((kwargs['host'], kwargs['port']))
            self.conn.settimeout(None)
        elif connection_type == 'serial':
            self.conn = serial.Serial(
                kwargs['device'],
                kwargs['baud'],
                timeout=kwargs.get('timeout', 1),
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
        else:
            raise ValueError("Unknown connection type")

    def sendall(self, data):
        if self.connection_type == 'tcp':
            self.conn.sendall(data)
        elif self.connection_type == 'serial':
            self.conn.write(data)

    def recv(self, bufsize):
        if self.connection_type == 'tcp':
            return self.conn.recv(bufsize)
        elif self.connection_type == 'serial':
            return self.conn.read(bufsize)

    def close(self):
        self.conn.close()

    def is_connected(self):
        if self.connection_type == 'tcp':
            try:
                self.conn.send(b'')  # Sending empty bytes to check connection
                return True
            except:
                return False
        elif self.connection_type == 'serial':
            return self.conn.is_open

# ------------------------------------------------------------------------------
#                          AX.25 ENCODING FUNCTIONS
# ------------------------------------------------------------------------------
def encode_callsign(callsign, last=False):
    parts = callsign.split('-')
    call_only = parts[0]
    ssid = int(parts[1]) if len(parts) > 1 else 0

    # Pad callsign to 6 chars
    call_only = call_only.ljust(6)

    encoded = bytearray(7)
    for i in range(6):
        encoded[i] = ord(call_only[i]) << 1

    encoded[6] = (ssid & 0x0F) << 1
    if last:
        encoded[6] |= 0x01
    return encoded

def build_kiss_frame(raw_aprs_packet):
    if ':' not in raw_aprs_packet:
        raise ValueError("Missing ':' in packet.")

    header_part, info_part = raw_aprs_packet.split(':', 1)
    info_part = info_part or ''

    if '>' not in header_part:
        raise ValueError("Missing '>' to separate source/dest.")
    source, dest_and_path = header_part.split('>', 1)
    parts = dest_and_path.split(',')
    destination = parts[0]
    path_list = parts[1:] if len(parts) > 1 else []

    address_fields = [destination, source] + path_list
    encoded_addresses = []
    for i, addr in enumerate(address_fields):
        encoded_addresses.append(encode_callsign(addr, last=(i==len(address_fields)-1)))

    ax25_frame = bytearray()
    for addr in encoded_addresses:
        ax25_frame.extend(addr)

    ax25_frame.append(0x03)  # UI frame
    ax25_frame.append(0xF0)  # No layer 3
    ax25_frame.extend(info_part.encode('ascii', errors='ignore'))

    kiss_frame = bytearray()
    kiss_frame.append(KISS_FLAG)
    kiss_frame.append(KISS_CMD_DATA)
    kiss_frame.extend(ax25_frame)
    kiss_frame.append(KISS_FLAG)
    return kiss_frame

# ------------------------------------------------------------------------------
#                          LOCATION HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def decimal_to_ddmm_mm(value, is_lat=True):
    negative = (value < 0)
    value = abs(value)
    degrees = int(value)
    minutes = (value - degrees) * 60.0

    if is_lat:
        deg_str = f"{degrees:02d}"
    else:
        deg_str = f"{degrees:03d}"

    min_str = f"{minutes:05.2f}"
    if is_lat:
        hemi = 'S' if negative else 'N'
    else:
        hemi = 'W' if negative else 'E'

    return f"{deg_str}{min_str}", hemi

# ------------------------------------------------------------------------------
#                       PACKET PROCESSING & RECEIVER
# ------------------------------------------------------------------------------
def decode_callsign(encoded):
    callsign = ''
    for b in encoded[:6]:
        char = chr(b >> 1)
        if char == '`':
            char = ' '
        callsign += char
    callsign = callsign.rstrip()
    ssid_byte = encoded[6]
    ssid = (ssid_byte >> 1) & 0x0F
    if ssid != 0:
        callsign += f"-{ssid}"
    return callsign

def parse_ax25_frame(frame):
    if len(frame) < 16:
        if config.get('debug'):
            print("KISS frame too short.")
        return
    address_fields = []
    index = 0
    while index+7 <= len(frame):
        address = frame[index:index+7]
        callsign = decode_callsign(address)
        address_fields.append(callsign)
        if address[6] & 0x01:
            index += 7
            break
        index += 7
    if len(address_fields) < 2:
        return

    destination = address_fields[0]
    source = address_fields[1]
    path = address_fields[2:] if len(address_fields) > 2 else []

    if index+2 > len(frame):
        return

    control = frame[index]
    pid = frame[index+1]
    info = frame[index+2:]
    return {
        'source': source,
        'destination': destination,
        'path': path,
        'control': control,
        'pid': pid,
        'info': info
    }

def decode_aprs(full_packet):
    try:
        return aprslib.parse(full_packet)
    except Exception as e:
        if config.get('debug'):
            print(f"APRS decode error: {e}")
        return None

# ------------------------------------------------------------------------------
#                           UDP Forwarding (iGate) + MQTT-FORWARD
# ------------------------------------------------------------------------------
def send_via_udp(igate_callsign, raw_aprs_packet, packet_type="tx"):
    """
    Sends a JSON payload to lora.link9.net:1515 via UDP:
    {
      "igate": igate_callsign,
      "type": packet_type,
      "content": raw_aprs_packet
    }

    Also, if --mqtt-forward is enabled, publishes that
    same JSON to MQTT topic kisstnc/payload via MQTT (if mqtt_manager is available).
    """
    payload = {
        "igate": igate_callsign,
        "type": packet_type,
        "content": raw_aprs_packet
    }

    if config.get('debug'):
        print("Sending via UDP (JSON):")
        print(json.dumps(payload, indent=2))
    
    # Send via UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(json.dumps(payload).encode('utf-8'), UDP_TARGET)
    finally:
        sock.close()

    # ### MQTT-FORWARD: Publish the same payload if requested
    if mqtt_forward and mqtt_manager:
        mqtt_payload_str = json.dumps(payload)
        try:
            mqtt_manager.publish_payload("kisstnc/payload", mqtt_payload_str)
        except Exception as e:
            print("[MQTT-FORWARD] Error publishing to kisstnc/payload:", e)

def loopback_tx_packet(raw_aprs_packet, igate_callsign=None):
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Ensure UDP send is performed regardless of APRS decode success
        if igate_callsign:
            send_via_udp(igate_callsign, raw_aprs_packet, packet_type="tx")
        
        aprs_data = decode_aprs(raw_aprs_packet)
        if aprs_data:
            aprs_data['timestamp'] = current_time
            aprs_data['type'] = 'tx'

            socketio.emit('aprs_packet', aprs_data)
            packet_history.append(aprs_data)

            if not no_log:
                with open(filename, 'a') as yf:
                    yaml.dump(aprs_data, yf, sort_keys=False, explicit_start=True)

            if config.get('debug'):
                print("APRS Parsed Data (TX):", aprs_data)
        else:
            if config.get('debug'):
                print(f"APRS decode failed for packet: {raw_aprs_packet}")
            # Emit the raw packet over WebSockets with timestamp
            socketio.emit('aprs_packet', { "raw": raw_aprs_packet, "timestamp": current_time })
            # Append raw packet with timestamp to history
            packet_history.append({ "raw": raw_aprs_packet, "timestamp": current_time })
            if not no_log:
                with open(filename, 'a') as yf:
                    yaml.dump({"raw": raw_aprs_packet, "timestamp": current_time},
                              yf, sort_keys=False, explicit_start=True)

    except Exception as e:
        print("[ERROR] loopback_tx_packet:", e)

# ------------------------------------------------------------------------------
#                           KISS Frame Handler
# ------------------------------------------------------------------------------
def handle_kiss_frame(frame, filename, no_log=False, igate_callsign=None):
    if len(frame) < 1:
        if config.get('debug'):
            print("KISS frame too short.")
        return

    cmd = frame[0]
    if cmd != KISS_CMD_DATA:
        print(f"Unsupported KISS command: {cmd}")
        return

    ax25_frame = frame[1:]
    parsed = parse_ax25_frame(ax25_frame)
    if not parsed:
        # Forward raw packet to MQTT (if enabled)
        if mqtt_forward and mqtt_manager:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_aprs_packet = frame.hex()  # As a fallback
            payload = {
                "igate": igate_callsign,
                "type": "rx",
                "content": full_aprs_packet,  # The unparsed raw packet
                "timestamp": current_time
            }
            try:
                mqtt_manager.publish_payload("kisstnc/payload", json.dumps(payload))
            except Exception as e:
                print("[MQTT] Error publishing raw packet:", e)
        return

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if config.get('debug'):
        print(f"\n--- Received KISS Frame ---\nTimestamp: {current_time}")
        print("Parsed AX.25:", parsed)

    to_field = parsed['destination']
    if parsed['path']:
        to_field += ',' + ','.join(parsed['path'])
    try:
        info_str = parsed['info'].decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        info_str = parsed['info'].decode('utf-8', errors='replace')

    # Trim leading "}" for third-party traffic
    if info_str.startswith(':}'):
        colon_idx = info_str.find(':}')
        if colon_idx != -1:
            info_str = info_str[colon_idx + 2:]
    elif info_str.startswith('}'):
        info_str = info_str[1:]

    full_aprs_packet = f"{parsed['source']}>{to_field}:{info_str}"

    # Forward via UDP (and possibly MQTT if -M)
    if igate_callsign:
        send_via_udp(igate_callsign, full_aprs_packet, packet_type="rx")

    aprs_data = decode_aprs(full_aprs_packet)
    if aprs_data:
        aprs_data['timestamp'] = current_time
        aprs_data['type'] = 'rx'
        socketio.emit('aprs_packet', aprs_data)
        packet_history.append(aprs_data)

        if not no_log:
            with open(filename, 'a') as yf:
                yaml.dump(aprs_data, yf, sort_keys=False, explicit_start=True)

        if config.get('debug'):
            print("APRS Parsed Data (RX):", aprs_data)
    else:
        if config.get('debug'):
            print(f"APRS decode failed for packet: {full_aprs_packet}")
        # Emit the raw packet over WebSockets with timestamp
        socketio.emit('aprs_packet', { "raw": full_aprs_packet, "timestamp": current_time })
        # Append raw packet with timestamp to history
        packet_history.append({ "raw": full_aprs_packet, "timestamp": current_time })
        if not no_log:
            with open(filename, 'a') as yf:
                yaml.dump({"raw": full_aprs_packet, "timestamp": current_time},
                      yf, sort_keys=False, explicit_start=True)

# ------------------------------------------------------------------------------
#                           MQTT MANAGER
# ------------------------------------------------------------------------------
class MqttManager:
    """
    Handles MQTT: connect, subscribe, publish. Auto-reconnect via loop_forever.
    Subscribes to topic_state for each channel with mqtt=True.
    (No longer subscribing to cmd topics to avoid echo.)
    """
    def __init__(self, host, port, use_tls, username, password, telemetry_manager):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.telemetry_manager = telemetry_manager

        self.client = mqtt.Client()
        if self.username:
            self.client.username_pw_set(self.username, self.password)
        if self.use_tls:
            self.client.tls_set()

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

        # Only store references for "state" topics
        self.channels_by_topic = {}

        self._connect_thread = threading.Thread(target=self.connect_loop, daemon=True)
        self._connect_thread.start()

    def connect_loop(self):
        while True:
            try:
                print(f"Connecting to MQTT {self.host}:{self.port} TLS={self.use_tls}")
                self.client.connect(self.host, self.port, keepalive=60)
                self.client.loop_forever()
            except Exception as e:
                print(f"[MQTT] Connection error: {e}; retry in 5s...")
                time.sleep(5)

    def on_connect(self, client, userdata, flags, rc):
        print("[MQTT] Connected with rc=", rc)
        self.resubscribe_all()

    def on_disconnect(self, client, userdata, rc):
        print("[MQTT] Disconnected with rc=", rc)

    def on_message(self, client, userdata, msg):
        topic = msg.topic
        payload_str = msg.payload.decode('utf-8', errors='ignore').strip()

        key_state = (topic, "state")
        if key_state in self.channels_by_topic:
            from_call, ch_num = self.channels_by_topic[key_state]
            self._update_channel_from_mqtt(from_call, ch_num, payload_str)

    def _update_channel_from_mqtt(self, from_call, channel, payload_str):
        """
        Compare inbound state vs. stored channel value to 2 decimal places
        for analogue channels; skip if no real change.
        """
        with self.telemetry_manager.lock:
            channels = self.telemetry_manager.state.get(from_call, {}).get('channels', {})
            ch_data = channels.get(channel)
            if not ch_data or not ch_data.get('mqtt'):
                return

            is_analogue = (1 <= channel <= 5)

            # Remove commas
            payload_str = payload_str.replace(',', '')

            if is_analogue:
                # parse new_val as float
                try:
                    new_val = float(payload_str)
                except ValueError:
                    if config.get('debug'):
                        print(f"[MQTT] Invalid float for ch{channel}: '{payload_str}'")
                    return

                old_val = ch_data['value']

                # If old_val isn't a float, try to parse it:
                if not isinstance(old_val, float):
                    try:
                        old_val = float(old_val)
                    except:
                        old_val = None

                if old_val is not None and round(old_val, 2) == round(new_val, 2):
                    if config.get('debug'):
                        print(f"[MQTT] ch{channel} no real change: old={old_val}, new={new_val}")
                    return

                ch_data['value'] = new_val
                self.telemetry_manager.save_state()

                if config.get('debug'):
                    print(f"[MQTT] Updated channel {channel} to {new_val}")

                changes = {
                    'parameter_changed': False,
                    'unit_changed': False,
                    'value_changed': True,
                    'eqns_changed': False,
                    'mqtt_changed': False
                }
                messages = self.telemetry_manager.generate_telemetry_messages(from_call, changes)
                for msg in messages:
                    outgoing_aprs_queue.put(msg)
            else:
                # digital channel
                val_lower = payload_str.lower()
                if val_lower in ['on','true','1']:
                    new_val = '1'
                elif val_lower in ['off','false','0']:
                    new_val = '0'
                else:
                    if config.get('debug'):
                        print(f"[MQTT] Invalid digital payload for ch{channel}: '{payload_str}'")
                    return

                old_val = ch_data['value']
                if old_val == new_val:
                    if config.get('debug'):
                        print(f"[MQTT] ch{channel} no real change: old={old_val}, new={new_val}")
                    return

                ch_data['value'] = new_val
                self.telemetry_manager.save_state()
                if config.get('debug'):
                    print(f"[MQTT] Updated channel {channel} to {new_val}")

                changes = {
                    'parameter_changed': False,
                    'unit_changed': False,
                    'value_changed': True,
                    'eqns_changed': False,
                    'mqtt_changed': False
                }
                messages = self.telemetry_manager.generate_telemetry_messages(from_call, changes)
                for msg in messages:
                    outgoing_aprs_queue.put(msg)

    def add_channel(self, from_call, channel, topic_state, _topic_cmd):
        """
        Only subscribe to the 'state' topic. We skip cmd topic to avoid echo.
        """
        self.channels_by_topic[(topic_state, "state")] = (from_call, channel)
        self.resubscribe_all()

    def remove_channel(self, topic_state, _topic_cmd):
        """
        Remove only from the 'state' topic references.
        """
        self.channels_by_topic.pop((topic_state, "state"), None)
        self.resubscribe_all()

    def resubscribe_all(self):
        if self.client.is_connected():
            for (topic, which) in self.channels_by_topic:
                self.client.subscribe(topic, qos=0)
                if config.get('debug'):
                    print(f"[MQTT] Subscribed to {topic} ({which})")

    def publish_cmd(self, topic_cmd, value, retained=False):
        """
        We do not subscribe to 'cmd' topics. We only publish them here.
        """
        if not self.client.is_connected():
            return
        try:
            # Remove commas from 'value' just in case
            value_str = str(value).replace(',', '')
            self.client.publish(topic_cmd, value_str, qos=0, retain=retained)
        except Exception as e:
            print(f"[MQTT] Publish error to {topic_cmd}: {e}")

    def publish_payload(self, topic, payload_str):
        if not self.client.is_connected():
            return
        try:
            self.client.publish(topic, payload_str, qos=0, retain=False)
        except Exception as e:
            print(f"[MQTT] Publish error to {topic}: {e}")

# ------------------------------------------------------------------------------
#                           TELEMETRY MANAGER
# ------------------------------------------------------------------------------
class TelemetryManager:
    def __init__(self, filepath='config/telemetry.yaml'):
        self.filepath = filepath
        self.lock = threading.RLock()
        self.state = {}
        self.load_state()
        print("TelemetryManager initialized.")

    def load_state(self):
        if os.path.exists(self.filepath):
            with self.lock:
                try:
                    with open(self.filepath, 'r') as f:
                        self.state = yaml.safe_load(f) or {}
                        print(f"Loaded telemetry from {self.filepath}")
                except yaml.YAMLError as e:
                    print(f"Error loading telemetry: {e}")
                    self.state = {}
        else:
            print("No existing telemetry file found.")
            self.state = {}

    def save_state(self):
        with self.lock:
            try:
                with open(self.filepath, 'w') as f:
                    yaml.dump(self.state, f)
                if config.get('debug'):
                    print(f"Saved telemetry state to {self.filepath}")
            except Exception as e:
                print(f"Error saving telemetry: {e}")

    def get_next_sequence(self, from_call):
        with self.lock:
            seq = self.state.get(from_call, {}).get('sequence', 0)
            next_seq = (seq+1) % 1000
            if from_call not in self.state:
                self.state[from_call] = {'sequence': next_seq, 'channels': {}}
            else:
                self.state[from_call]['sequence'] = next_seq
            self.save_state()
            return f"{next_seq:03d}"

    # Float-tolerant eqns compare function
    def _eqns_are_same(self, eqns_new, eqns_old, epsilon=1e-9):
        """Return True if eqns_new and eqns_old have the same length
        and each float is within epsilon of the other."""
        if not isinstance(eqns_new, list) or not isinstance(eqns_old, list):
            return False
        if len(eqns_new) != len(eqns_old):
            return False
        for a, b in zip(eqns_new, eqns_old):
            if abs(a - b) > epsilon:
                return False
        return True

    def update_channel(self, from_call, channel,
                       parameter=None, unit=None,
                       value=None, eqns=None,
                       mqtt_enabled=None,
                       topic_state=None, topic_cmd=None,
                       mqtt_retained=None):
        changes = {
            'parameter_changed': False,
            'unit_changed': False,
            'value_changed': False,
            'eqns_changed': False,
            'mqtt_changed': False
        }
        with self.lock:
            if from_call not in self.state:
                self.state[from_call] = {'sequence': 0, 'channels': {}}
            channels = self.state[from_call]['channels']

            is_analogue = (1 <= channel <= 5)

            if channel not in channels:
                # remove commas
                if parameter is not None:
                    parameter = parameter.replace(',', '')
                if unit is not None:
                    unit = unit.replace(',', '')

                if parameter is None or unit is None or value is None:
                    raise ValueError("For new channel, 'parameter','unit','value' are required.")

                if is_analogue:
                    if isinstance(value, str):
                        value = value.replace(',', '')
                    try:
                        val_float = float(value)
                    except:
                        raise ValueError("Analogue channel value must be float.")
                    if eqns:
                        try:
                            eqns_f = [float(x) for x in eqns.split(',')]
                            if len(eqns_f) != 3:
                                raise ValueError
                        except:
                            raise ValueError("Invalid eqns for analogue.")
                    else:
                        eqns_f = [0.0, 1.0, 0.0]
                    ch_data = {
                        'parameter': parameter,
                        'unit': unit,
                        'value': val_float,
                        'eqns': eqns_f
                    }
                else:
                    # digital
                    if isinstance(value, str):
                        value = value.replace(',', '')
                    ch_data = {
                        'parameter': parameter,
                        'unit': unit
                    }
                    ch_data['value'] = self._convert_digital_value(value)

                if mqtt_enabled:
                    if not topic_state or not topic_cmd:
                        raise ValueError("mqtt=true requires topic_state & topic_cmd.")
                    ch_data['mqtt'] = True
                    ch_data['topic_state'] = topic_state
                    ch_data['topic_cmd'] = topic_cmd
                    if mqtt_retained is True:
                        ch_data['mqtt_retained'] = True
                    else:
                        ch_data['mqtt_retained'] = False
                else:
                    ch_data['mqtt'] = False

                channels[channel] = ch_data
                changes.update({
                    'parameter_changed': True,
                    'unit_changed': True,
                    'value_changed': True,
                    'eqns_changed': is_analogue,
                    'mqtt_changed': bool(mqtt_enabled)
                })
                self.save_state()
                return changes
            else:
                ch_data = channels[channel]

                old_topic_state = ch_data.get('topic_state')

                if parameter is not None:
                    parameter = parameter.replace(',', '')
                    if ch_data.get('parameter') != parameter:
                        ch_data['parameter'] = parameter
                        changes['parameter_changed'] = True

                if unit is not None:
                    unit = unit.replace(',', '')
                    if ch_data.get('unit') != unit:
                        ch_data['unit'] = unit
                        changes['unit_changed'] = True

                if value is not None:
                    if is_analogue:
                        if isinstance(value, str):
                            value = value.replace(',', '')
                        try:
                            new_val = float(value)
                        except:
                            raise ValueError("Analogue needs float value.")
                        if ch_data['value'] != new_val:
                            ch_data['value'] = new_val
                            changes['value_changed'] = True
                    else:
                        if isinstance(value, str):
                            value = value.replace(',', '')
                        new_dig = self._convert_digital_value(value)
                        if ch_data['value'] != new_dig:
                            ch_data['value'] = new_dig
                            changes['value_changed'] = True

                if eqns is not None:
                    if not is_analogue:
                        raise ValueError("EQNS only for analogue channels.")
                    try:
                        eqns_f = [float(x) for x in eqns.split(',')]
                        if len(eqns_f) != 3:
                            raise ValueError
                    except:
                        raise ValueError("Invalid eqns format.")
                    old_eqns = ch_data.get('eqns') or []
                    if not self._eqns_are_same(eqns_f, old_eqns):
                        ch_data['eqns'] = eqns_f
                        changes['eqns_changed'] = True

                if mqtt_enabled is True:
                    if not topic_state or not topic_cmd:
                        raise ValueError("mqtt=true requires topic_state & topic_cmd.")
                    if not ch_data.get('mqtt'):
                        changes['mqtt_changed'] = True
                    else:
                        if topic_state != old_topic_state:
                            changes['mqtt_changed'] = True

                    ch_data['mqtt'] = True
                    ch_data['topic_state'] = topic_state
                    ch_data['topic_cmd'] = topic_cmd
                    if mqtt_retained is True:
                        ch_data['mqtt_retained'] = True
                    elif mqtt_retained is False:
                        ch_data['mqtt_retained'] = False
                elif mqtt_enabled is False:
                    if ch_data.get('mqtt'):
                        changes['mqtt_changed'] = True
                    ch_data['mqtt'] = False
                    ch_data.pop('topic_state', None)
                    ch_data.pop('topic_cmd', None)
                    ch_data.pop('mqtt_retained', None)

                self.save_state()

                changes['old_topic_state'] = old_topic_state
                return changes

    def _convert_digital_value(self, val):
        if isinstance(val, bool):
            return '1' if val else '0'
        if isinstance(val, int) and val in (0,1):
            return str(val)
        if isinstance(val, str):
            vl = val.lower()
            if vl in ['0','off','false']:
                return '0'
            elif vl in ['1','on','true']:
                return '1'
        raise ValueError("Digital channel value must be boolean/0/1/true/false/on/off.")

    def delete_channel(self, from_call, channel):
        with self.lock:
            if from_call not in self.state:
                return False
            channels = self.state[from_call].get('channels', {})
            if channel not in channels:
                return False
            del channels[channel]
            self.save_state()
            return True

    def get_telemetry_data(self):
        with self.lock:
            return self.state.copy()

    def generate_telemetry_messages(self, from_call, changes):
        messages = []
        telemetry = self.state.get(from_call, {})
        if not telemetry:
            return messages

        if changes.get('parameter_changed'):
            parm = self.construct_parm_message(from_call)
            if parm:
                messages.append(parm)

        if changes.get('unit_changed'):
            unit = self.construct_unit_message(from_call)
            if unit:
                messages.append(unit)

        if changes.get('eqns_changed'):
            eq = self.construct_eqns_message(from_call)
            if eq:
                messages.append(eq)

        if changes.get('value_changed'):
            t = self.construct_t_message(from_call)
            if t:
                messages.append(t)
        return messages

    def construct_parm_message(self, from_call):
        with self.lock:
            telem = self.state.get(from_call, {})
            chs = telem.get('channels', {})
            if not chs:
                return None
            param_list = []
            for ch in range(1,14):
                if ch in chs:
                    param_list.append(chs[ch].get('parameter',''))
                else:
                    param_list.append('')
            parm_str = ",".join(param_list)
            return f"{from_call}>APRS,WIDE1-1::{from_call}:PARM.{parm_str}"

    def construct_unit_message(self, from_call):
        with self.lock:
            telem = self.state.get(from_call, {})
            chs = telem.get('channels', {})
            if not chs:
                return None
            unit_list = []
            for ch in range(1,14):
                if ch in chs:
                    unit_list.append(chs[ch].get('unit',''))
                else:
                    unit_list.append('')
            unit_str = ",".join(unit_list)
            return f"{from_call}>APRS,WIDE1-1::{from_call}:UNIT.{unit_str}"

    def construct_t_message(self, from_call):
        with self.lock:
            telem = self.state.get(from_call, {})
            chs = telem.get('channels', {})
            if not chs:
                return None
            seq = self.get_next_sequence(from_call)
            analogs = ['']*5
            digits = ['0']*8
            for ch in range(1,14):
                if ch in chs:
                    val = chs[ch]['value']
                    if 1 <= ch <= 5:
                        analogs[ch-1] = f"{val:.2f}"
                    else:
                        digits[ch-6] = val
            dig_str = ''.join(digits)
            return f"{from_call}>APRS,WIDE1-1:T#{seq}," + ",".join(analogs) + "," + dig_str

    def construct_eqns_message(self, from_call):
        with self.lock:
            telem = self.state.get(from_call, {})
            if not telem:
                return None
            chs = telem.get('channels', {})
            eq_list = []
            for cnum in range(1,6):
                if cnum in chs and 'eqns' in chs[cnum]:
                    eq_list.extend(map(str, chs[cnum]['eqns']))
                else:
                    eq_list.extend(['0','1','0'])
            eq_str = ",".join(eq_list)
            return f"{from_call}>APRS,WIDE1-1::{from_call}:EQNS.{eq_str}"

    def mark_sent(self, from_call, changes):
        pass

# ------------------------------------------------------------------------------
#                           RECONNECT & RECEIVE THREAD
# ------------------------------------------------------------------------------
def reconnect(connection_type, config, filename, no_log, igate_callsign, telemetry_manager):
    global tnc_connection
    while True:
        try:
            print(f"Attempting reconnect to {connection_type}...")
            if connection_type == 'tcp':
                new_conn = TNCConnection('tcp', host=config['host'], port=config['port'], timeout=5)
            elif connection_type == 'serial':
                new_conn = TNCConnection('serial', device=config['device'], baud=config['baud'], timeout=1)
            else:
                raise ValueError("Unknown connection type")
            print("Reconnected to TNC.")
            tnc_connection = new_conn
            start_receive_thread(new_conn, connection_type, config, filename, no_log, igate_callsign, telemetry_manager)
            return
        except Exception as e:
            print(f"Reconn failed: {e}, retry in 5s...")
            time.sleep(5)

def receive_data(conn, connection_type, config, filename, no_log, igate_callsign, telemetry_manager):
    buffer = bytearray()
    while True:
        try:
            data = conn.recv(4096)
            if connection_type == 'tcp':
                # If zero bytes on TCP, it really is closed
                if not data:
                    print("TNC closed connection.")
                    conn.close()
                    reconnect(connection_type, config, filename, no_log, igate_callsign, telemetry_manager)
                    break
            else:
                # If zero bytes on Serial, it just means no data arrived yet
                if len(data) == 0:
                    continue

            # >>> If proxy is enabled, forward raw data to all connected proxy clients
            if proxy_clients is not None:
                bridging_broadcast(data)

            buffer.extend(data)
            while True:
                if KISS_FLAG in buffer:
                    flag_index = buffer.index(KISS_FLAG)
                    if flag_index != 0:
                        buffer = buffer[flag_index:]
                    if buffer.count(KISS_FLAG) < 2:
                        break
                    start = 0
                    end = buffer.find(KISS_FLAG, start+1)
                    if end == -1:
                        break
                    frame = buffer[start+1:end]
                    handle_kiss_frame(frame, filename, no_log, igate_callsign)
                    buffer = buffer[end:]
                else:
                    buffer.clear()
                    break
        except Exception as e:
            print("Error receiving data:", e)
            conn.close()
            reconnect(connection_type, config, filename, no_log, igate_callsign, telemetry_manager)
            break

def start_receive_thread(conn, connection_type, config, filename, no_log, igate_callsign, telemetry_manager):
    recv_thread = threading.Thread(
        target=receive_data,
        args=(conn, connection_type, config, filename, no_log, igate_callsign, telemetry_manager),
        daemon=True
    )
    recv_thread.start()

# ------------------------------------------------------------------------------
#                           SEND FRAMES FUNCTION
# ------------------------------------------------------------------------------
def send_frames(send_delay_ms):
    global outgoing_aprs_queue, aprs_enabled, igate_callsign, aprs_host, aprs_port, aprs_socket, tnc_connection, connection_type
    while True:
        raw_packet = outgoing_aprs_queue.get()
        try:
            if raw_packet is None:
                print("Send thread stopping.")
                break

            if connection_type == 'aprs-is':
                # Only send to APRS-IS
                send_to_aprs_is(raw_packet)
            else:
                # Send via TNC
                if tnc_connection is None or not tnc_connection.is_connected():
                    print("TNC connection unavailable. Re-enqueueing packet and waiting...")
                    outgoing_aprs_queue.put(raw_packet)
                    time.sleep(5)
                    continue  # Skip processing and reattempt later

                if config.get('debug'):
                    print(f"Sending TNC packet: {raw_packet}")
                try:
                    kiss_frame = build_kiss_frame(raw_packet)
                except ValueError as ve:
                    print("[ERROR] build_kiss_frame:", ve)
                    continue  # Skip marking task_done; it will be handled in finally

                try:
                    tnc_connection.sendall(kiss_frame)
                except Exception as e:
                    print("[ERROR] sendall:", e)
                    # Close connection and set to None to trigger reconnection
                    if tnc_connection:
                        tnc_connection.close()
                        tnc_connection = None
                    continue  # Skip marking task_done; it will be handled in finally

                loopback_tx_packet(raw_packet, igate_callsign)

                # Send to APRS-IS if enabled with modified path
                if aprs_enabled and aprs_callsign:
                    send_to_aprs_is(raw_packet)

            time.sleep(send_delay_ms/1000.0)
        except Exception as e:
            print("[ERROR] send_frames thread:", e)
        finally:
            outgoing_aprs_queue.task_done()

# ------------------------------------------------------------------------------
#                           TELEMETRY BACKGROUND TASK
# ------------------------------------------------------------------------------
def telemetry_background_task(telemetry_manager, interval_minutes):
    while True:
        telem_data = telemetry_manager.get_telemetry_data()
        for from_call in telem_data:
            has_eqns = any(
                1 <= ch <= 5 and 'eqns' in ch_data
                for ch, ch_data in telem_data[from_call]['channels'].items()
            )
            msgs = telemetry_manager.generate_telemetry_messages(from_call, {
                'parameter_changed': True,
                'unit_changed': True,
                'value_changed': True,
                'eqns_changed': has_eqns,
                'mqtt_changed': False
            })
            for m in msgs:
                outgoing_aprs_queue.put(m)
        time.sleep(interval_minutes * 60)

# ------------------------------------------------------------------------------
#                           APRS-IS FUNCTIONS
# ------------------------------------------------------------------------------
def aprs_pass(callsign):
    """
    Generates APRS passcode based on the callsign.
    Mirrors the PHP aprspass function.
    """
    stophere = callsign.find('-')
    if stophere != -1:
        callsign = callsign[:stophere]
    realcall = callsign.upper()[:10]

    # Initialise hash
    hash_val = 0x73E2
    i = 0
    length = len(realcall)

    # Hash callsign two bytes at a time
    while i < length:
        hash_val ^= ord(realcall[i]) << 8
        if i + 1 < length:
            hash_val ^= ord(realcall[i + 1])
        i += 2

    # Mask off the high bit so the number is always positive
    return hash_val & 0x7FFF

def connect_aprs_is():
    """
    Establishes a connection to the APRS-IS server and logs in.
    Enhanced with detailed debug outputs.
    """
    global aprs_socket, aprs_callsign, aprs_host, aprs_port, config
    while True:
        try:
            if config.get('debug'):
                print(f"Connecting to APRS-IS {aprs_host}:{aprs_port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((aprs_host, aprs_port))
            sock.settimeout(None)
            aprs_socket = sock
            if config.get('debug'):
                print("Connected to APRS-IS server.")

            # Generate passcode
            password = aprs_pass(aprs_callsign)
            aprs_filter = config.get('aprs_filter', 'm/100')
            login_str = f"user {aprs_callsign} pass {password} vers lora-aprs.live-client 1.0.0 filter {aprs_filter} \r\n"

            if config.get('debug'):
                print(f"Sending login string: {login_str.strip()}")

            sock.sendall(login_str.encode('utf-8'))

            # Read server response lines until logresp is received or timeout
            response = ""
            while True:
                try:
                    line = sock.recv(1024).decode('utf-8', errors='ignore')
                    if not line:
                        break
                    response += line
                    if config.get('debug'):
                        print(f"Received from APRS-IS: {line.strip()}")
                    if "# LOGRESP" in line.upper():
                        break
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"Error reading from APRS-IS: {e}")
                    break

            # Check for successful login keywords
            if any(keyword in response.upper() for keyword in ["LOGIN OK", "USERID", "NOERROR", "# LOGRESP"]):
                if config.get('debug'):
                    print("Successfully logged in to APRS-IS.")
                break
            else:
                print(f"Login failed: {response}")
                sock.close()
                time.sleep(5)
        except Exception as e:
            print(f"Error connecting/logging into APRS-IS: {e}")
            time.sleep(5)

def modify_path_to_tcpip(raw_packet):
    """
    Modifies the path in the APRS packet to 'TCPIP'.
    """
    try:
        if '>' not in raw_packet or ':' not in raw_packet:
            return raw_packet  # Cannot parse, return as is
        header, info = raw_packet.split(':', 1)
        source, rest = header.split('>', 1)
        parts = rest.split(',', 1)
        destination = parts[0]
        # Replace existing path(s) with 'TCPIP'
        new_header = f"{source}>{destination},TCPIP"
        return f"{new_header}:{info}"
    except Exception as e:
        print(f"[WARNING] Failed to modify path for APRS-IS: {e}")
        return raw_packet  # Return original packet if any error occurs

def send_to_aprs_is(packet):
    """
    Sends a modified APRS packet to the APRS-IS server with the path set to 'TCPIP'.
    """
    global aprs_socket, aprs_callsign, aprs_host, aprs_port, config, aprs_lock, aprs_enabled
    if not aprs_enabled:
        return

    # Modify the packet's path to 'TCPIP' for APRS-IS
    modified_packet = modify_path_to_tcpip(packet)

    with aprs_lock:
        if aprs_socket is None:
            connect_aprs_is()

        try:
            aprs_socket.sendall((modified_packet + "\r\n").encode('utf-8'))
            if config.get('debug'):
                print(f"Sent to APRS-IS: {modified_packet}")
        except Exception as e:
            print(f"Error sending to APRS-IS: {e}")
            aprs_socket.close()
            aprs_socket = None
            # Attempt to reconnect
            connect_aprs_is()

def handle_aprs_is_packet(packet):
    """
    Parses and processes a packet received from APRS-IS.
    Forwards non-parseable raw packets to MQTT as raw data.
    """
    try:
        aprs_data = decode_aprs(packet)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if aprs_data:
            aprs_data['timestamp'] = current_time
            aprs_data['type'] = 'rx'
            
            socketio.emit('aprs_packet', aprs_data)
            packet_history.append(aprs_data)
    
            if not no_log:
                with open(filename, 'a') as yf:
                    yaml.dump(aprs_data, yf, sort_keys=False, explicit_start=True)
    
            if config.get('debug'):
                print("APRS-IS Parsed Data:", aprs_data)
        else:
            if config.get('debug'):
                print(f"APRS decode failed for packet: {packet}")
            
            raw_packet_info = {
                "raw": packet,
                "timestamp": current_time
            }
            
            socketio.emit('aprs_packet', raw_packet_info)
            packet_history.append(raw_packet_info)
    
            if config.get('mqtt_forward') and mqtt_manager and igate_callsign:
                mqtt_payload = {
                    "igate": igate_callsign,
                    "type": "raw",
                    "content": packet,
                    "timestamp": current_time
                }
                mqtt_payload_str = json.dumps(mqtt_payload)
                mqtt_topic = "kisstnc/payload"
                
                try:
                    mqtt_manager.publish_payload(mqtt_topic, mqtt_payload_str)
                    
                    if config.get('debug'):
                        print(f"[MQTT] Forwarded raw packet to topic '{mqtt_topic}': {mqtt_payload_str}")
                except Exception as e:
                    print(f"[MQTT] Error publishing raw packet to '{mqtt_topic}': {e}")
    
    except Exception as e:
        print(f"[ERROR] handle_aprs_is_packet: {e}")

def receive_aprs_is_data():
    """
    Listens for incoming data from APRS-IS and processes each packet.
    """
    global aprs_socket, config, packet_history
    buffer = ""
    while True:
        try:
            if aprs_socket is None:
                time.sleep(1)
                continue
            data = aprs_socket.recv(4096)
            if not data:
                print("APRS-IS connection closed by server.")
                aprs_socket.close()
                aprs_socket = None
                connect_aprs_is()
                continue
            buffer += data.decode('utf-8', errors='ignore')
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if config.get('debug'):
                    print(f"Received from APRS-IS: {line}")
                handle_aprs_is_packet(line)
        except Exception as e:
            print(f"Error receiving data from APRS-IS: {e}")
            if aprs_socket:
                aprs_socket.close()
                aprs_socket = None
            time.sleep(5)
            connect_aprs_is()

# ------------------------------------------------------------------------------
#                           API ENDPOINTS
# ------------------------------------------------------------------------------
@app.route('/api/send/raw', methods=['POST'])
def send_raw():
    global tnc_connection, outgoing_aprs_queue, aprs_enabled, igate_callsign, aprs_host, aprs_port, aprs_socket, connection_type
    if connection_type != 'aprs-is' and tnc_connection is None:
        return jsonify({"error":"TNC connection not available"}), 500

    data = request.get_json()
    if not data or 'packet' not in data:
        return jsonify({"error":"No 'packet' in JSON body"}), 400

    raw_pkt = data['packet']
    try:
        outgoing_aprs_queue.put(raw_pkt)
        return jsonify({"status":"sent"}), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route('/api/send/beacon', methods=['POST'])
def send_beacon():
    global tnc_connection, outgoing_aprs_queue, aprs_enabled, igate_callsign, aprs_host, aprs_port, aprs_socket, connection_type
    if connection_type != 'aprs-is' and tnc_connection is None:
        return jsonify({"error":"TNC connection not available"}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error":"No JSON body"}), 400

    from_call = data.get('from','').strip().upper()
    status_str = data.get('status','').strip()
    if not from_call or not status_str:
        return jsonify({"error":"'from' and 'status' must not be empty"}), 400

    path_str = data.get("path", "WIDE1-1").upper()
    pkt = f"{from_call}>BEACON,{path_str}:>{status_str}"
    try:
        outgoing_aprs_queue.put(pkt)
        return jsonify({"status":"sent"}), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route('/api/send/location', methods=['POST'])
def send_location():
    global tnc_connection, outgoing_aprs_queue, aprs_enabled, igate_callsign, aprs_host, aprs_port, aprs_socket, connection_type
    if connection_type != 'aprs-is' and tnc_connection is None:
        return jsonify({"error":"TNC connection not available"}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error":"No JSON body"}), 400

    from_call = data.get('from','').strip().upper()
    if not from_call:
        return jsonify({"error":"'from' cannot be empty"}), 400

    if 'latitude' not in data or 'longitude' not in data:
        return jsonify({"error":"Missing lat/lon"}), 400

    try:
        lat_val = float(data['latitude'])
        lon_val = float(data['longitude'])
    except:
        return jsonify({"error":"lat/lon must be valid floats"}),400

    to_call = data.get('to','APRS').upper()
    path_str = data.get('path','WIDE1-1').upper()
    symbol_table = data.get('symbol_table','/')
    symbol_char = data.get('symbol','L')

    comment = data.get('comment',None)
    if comment is not None:
        comment = comment.strip()
        if not comment:
            return jsonify({"error":"'comment' cannot be empty if provided"}),400

    lat_str, lat_ns = decimal_to_ddmm_mm(lat_val, True)
    lon_str, lon_ew = decimal_to_ddmm_mm(lon_val, False)

    info_str = f"!{lat_str}{lat_ns}{symbol_table}{lon_str}{lon_ew}{symbol_char}"
    if comment:
        info_str += comment

    pkt = f"{from_call}>{to_call},{path_str}:{info_str}"
    try:
        outgoing_aprs_queue.put(pkt)
        return jsonify({"status":"sent"}), 200
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route('/api/send/telemetry', methods=['POST','DELETE'])
def send_telemetry():
    global tnc_connection, telemetry_manager, mqtt_manager, aprs_enabled, igate_callsign, aprs_host, aprs_port, aprs_socket, connection_type
    if request.method == 'POST':
        if connection_type != 'aprs-is' and tnc_connection is None:
            return jsonify({"error":"TNC connection not available"}), 500

        data = request.get_json()
        if not data or 'from' not in data or 'channels' not in data:
            return jsonify({"error":"Must provide 'from' and 'channels'"}),400

        from_call = data['from'].strip().upper()
        chans = data['channels']
        if not isinstance(chans, list) or not chans:
            return jsonify({"error":"'channels' must be non-empty list"}),400

        overall_changes = {
            'parameter_changed': False,
            'unit_changed': False,
            'value_changed': False,
            'eqns_changed': False,
            'mqtt_changed': False
        }

        for ch_update in chans:
            if 'channel' not in ch_update or 'value' not in ch_update:
                return jsonify({"error":"Each channel object must have 'channel' & 'value'"}),400
            ch_num = ch_update['channel']
            val = ch_update['value']
            param = ch_update.get('parameter',None)
            unit = ch_update.get('unit',None)
            eqns = ch_update.get('eqns',None)

            mqtt_flag = ch_update.get('mqtt',None)
            topic_state = ch_update.get('topic_state',None)
            topic_cmd   = ch_update.get('topic_cmd',None)
            mqtt_retained_flag = ch_update.get('mqtt_retained', None)

            if not isinstance(ch_num, int) or not (1<=ch_num<=13):
                return jsonify({"error":"channel must be 1..13"}),400

            try:
                changes = telemetry_manager.update_channel(
                    from_call, ch_num,
                    parameter=param,
                    unit=unit,
                    value=val,
                    eqns=eqns,
                    mqtt_enabled=mqtt_flag,
                    topic_state=topic_state,
                    topic_cmd=topic_cmd,
                    mqtt_retained=mqtt_retained_flag
                )
                for k in overall_changes:
                    if changes.get(k):
                        overall_changes[k] = True

                with telemetry_manager.lock:
                    ch_data = telemetry_manager.state[from_call]['channels'][ch_num]
                    is_mqtt = ch_data.get('mqtt',False)

                    if mqtt_manager and changes.get('mqtt_changed'):
                        old_ts = changes.get('old_topic_state')

                        if is_mqtt:
                            new_ts = ch_data['topic_state']
                            new_tc = ch_data['topic_cmd']
                            if old_ts and old_ts != new_ts:
                                mqtt_manager.remove_channel(old_ts, None)
                            mqtt_manager.add_channel(from_call, ch_num, new_ts, new_tc)
                        else:
                            if old_ts:
                                mqtt_manager.remove_channel(old_ts, None)

            except ValueError as ve:
                return jsonify({"error":str(ve)}),400
            except Exception as e:
                return jsonify({"error":f"Telemetry update fail: {e}"}),500

        if any(overall_changes.values()):
            try:
                msgs = telemetry_manager.generate_telemetry_messages(from_call, overall_changes)
            except Exception as e:
                return jsonify({"error":f"Telemetry gen failed: {e}"}),500

            for m in msgs:
                outgoing_aprs_queue.put(m)

            try:
                telemetry_manager.mark_sent(from_call, overall_changes)
            except Exception as e:
                return jsonify({"error":f"Mark sent failed: {e}"}),500

            if overall_changes['value_changed'] and mqtt_manager:
                with telemetry_manager.lock:
                    for ch_update in chans:
                        ch_num = ch_update['channel']
                        ch_data = telemetry_manager.state[from_call]['channels'].get(ch_num, {})
                        if ch_data.get('mqtt'):
                            tc = ch_data['topic_cmd']
                            val_to_pub = ch_data['value']
                            retained_flag = ch_data.get('mqtt_retained', False)
                            mqtt_manager.publish_cmd(tc, val_to_pub, retained=retained_flag)

            return jsonify({"status":"telemetry sent"}),200
        else:
            return jsonify({"status":"no change in value"}),200

    else:  # DELETE
        data = request.get_json()
        if not data or 'from' not in data or 'channel' not in data:
            return jsonify({"error":"Must provide 'from' & 'channel'"}),400
        from_call = data['from'].strip().upper()
        ch_num = data['channel']
        if not isinstance(ch_num,int) or not (1<=ch_num<=13):
            return jsonify({"error":"channel must be 1..13"}),400

        with telemetry_manager.lock:
            ch_data = telemetry_manager.state.get(from_call,{}).get('channels',{}).get(ch_num)
            if ch_data and ch_data.get('mqtt'):
                if mqtt_manager and 'topic_state' in ch_data:
                    old_ts = ch_data['topic_state']
                    mqtt_manager.remove_channel(old_ts, None)

        success = telemetry_manager.delete_channel(from_call, ch_num)
        if success:
            return jsonify({"status":f"Channel {ch_num} deleted for {from_call}"}),200
        else:
            return jsonify({"error":f"Channel {ch_num} not found for {from_call}"}),404

@app.route('/api/receive/telemetry', methods=['GET'])
def receive_telemetry():
    global telemetry_manager
    from_call = request.args.get('from','').strip().upper()
    if not from_call:
        return jsonify({"error":"'from' query param is needed"}),400

    telem_data = telemetry_manager.get_telemetry_data()
    if from_call not in telem_data:
        return jsonify({"error":f"No telemetry for {from_call}"}),404

    channels = telem_data[from_call].get('channels',{})
    if not channels:
        return jsonify({"error":f"No channels for {from_call}"}),404

    resp_ch = []
    for ch_num in sorted(channels.keys()):
        c = channels[ch_num]
        ch_type = "analogue" if 1<=ch_num<=5 else "digital"
        info = {
            "channel": ch_num,
            "type": ch_type,
            "parameter": c.get('parameter',''),
            "unit": c.get('unit',''),
            "value": c.get('value','')
        }
        if ch_type=="analogue" and 'eqns' in c:
            info["eqns"] = ",".join(map(str,c['eqns']))

        info["mqtt"] = c.get('mqtt',False)
        info["mqtt_retained"] = c.get('mqtt_retained',False)
        info["topic_state"] = c.get('topic_state','')
        info["topic_cmd"]   = c.get('topic_cmd','')

        resp_ch.append(info)

    return jsonify({
        "from": from_call,
        "channels": resp_ch
    }),200

# ------------------------------------------------------------------------------
#                           SOCKET.IO EVENTS
# ------------------------------------------------------------------------------
@socketio.on('connect')
def handle_connect(auth):  # accept the argument
    global connected_ip, active_sids
    client_ip = request.remote_addr
    current_sid = request.sid

    if connected_ip is None:
        # No one connected yet, accept this IP
        connected_ip = client_ip
        print(f"No IP was connected; now using IP={connected_ip}.")
    else:
        # If a different IP arrives, disconnect all current sessions
        if connected_ip != client_ip:
            print(f"New IP {client_ip} connected. Disconnecting all clients from {connected_ip}...")
            for sid in list(active_sids.keys()):
                disconnect(sid=sid, namespace='/')

            connected_ip = client_ip

    # Track the new session
    active_sids[current_sid] = client_ip
    print(f"Client connected: SID={current_sid}, IP={client_ip}")

@socketio.on('disconnect')
def handle_disconnect():
    global connected_ip, active_sids
    current_sid = request.sid

    if current_sid in active_sids:
        ip = active_sids[current_sid]
        print(f"Client disconnected: SID={current_sid}, IP={ip}")
        del active_sids[current_sid]

        # If no sessions left from that IP, free up `connected_ip`
        still_has_sessions = any(stored_ip == ip for stored_ip in active_sids.values())
        if not still_has_sessions:
            connected_ip = None
            print(f"No more sessions from IP={ip}. The server is now free for a new IP.")
    else:
        print(f"Unknown SID disconnected: {current_sid}")


@socketio.on('connect', namespace='/logs')
def logs_connect():
    print("Client connected to /logs")

@socketio.on('disconnect', namespace='/logs')
def logs_disconnect():
    print("Client disconnected from /logs")

# ------------------------------------------------------------------------------
#                     PROXY (TRANSPARENT TCP BRIDGE) CODE
# ------------------------------------------------------------------------------
# Global set of connected proxy clients if proxy_enabled is true
proxy_clients = None

def bridging_broadcast(data):
    """
    Forwards raw data from TNC to all connected proxy clients.
    """
    global proxy_clients
    if proxy_clients is None:
        return
    to_remove = []
    for client in proxy_clients:
        try:
            client.sendall(data)
        except:
            to_remove.append(client)
    for c in to_remove:
        proxy_clients.remove(c)
        c.close()

def handle_proxy_client(client_socket):
    """
    Handles data from a single proxy client, forwarding it immediately to the TNC connection
    (without delay). If the TNC is not connected, the data is discarded.
    """
    global tnc_connection, proxy_clients
    buffer = bytearray()

    try:
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                # Client closed the connection
                break

            # Append new data to the buffer
            buffer.extend(chunk)

            # Repeatedly look for two 0xC0 flags, meaning we have a complete KISS frame
            while True:
                # If there's no 0xC0 at all, we wait for more data
                if KISS_FLAG not in buffer:
                    break

                # Find the first 0xC0
                start_index = buffer.index(KISS_FLAG)

                # Discard anything before that flag
                if start_index != 0:
                    buffer = buffer[start_index:]

                # If we only have one flag in the buffer, we don't have a full frame yet
                if buffer.count(KISS_FLAG) < 2:
                    break

                # Find the next 0xC0 after the first
                end_index = buffer.find(KISS_FLAG, start_index + 1)
                if end_index == -1:
                    break

                # Extract that entire KISS frame (including the second flag)
                frame = buffer[:end_index + 1]

                # Remove the frame bytes from the buffer
                buffer = buffer[end_index + 1:]

                # Forward this complete KISS frame to the TNC (if connected)
                if tnc_connection and tnc_connection.is_connected():
                    tnc_connection.sendall(frame)

    except Exception as e:
        print(f"[Proxy] Error handling client: {e}")

    finally:
        if proxy_clients is not None and client_socket in proxy_clients:
            proxy_clients.remove(client_socket)
        client_socket.close()


def start_proxy_server(port):
    """
    Starts a TCP server socket that listens on the specified port. For each new client,
    spawns a green thread to handle forwarding data from that client to the TNC.
    """
    server = eventlet.listen(('0.0.0.0', port))
    print(f"Proxy server listening on 0.0.0.0:{port} ...")

    def accept_clients(sock):
        while True:
            client_socket, addr = sock.accept()
            if proxy_clients is not None:
                proxy_clients.add(client_socket)
                print(f"[Proxy] Client connected from {addr}")
                eventlet.spawn_n(handle_proxy_client, client_socket)

    eventlet.spawn_n(accept_clients, server)

# ------------------------------------------------------------------------------
#                           MAIN FUNCTION
# ------------------------------------------------------------------------------
def main():
    load_settings()

    global DEBUG, tnc_connection, no_log, filename, igate_callsign
    global telemetry_manager, outgoing_aprs_queue
    global mqtt_manager, mqtt_host, mqtt_port, mqtt_tls, mqtt_user, mqtt_pass
    global mqtt_forward
    global aprs_enabled, aprs_callsign, aprs_host, aprs_port, aprs_socket
    global connection_type
    global proxy_clients

    connection_type = config['connection_type']

    host = config['host']
    port = config['port']
    device = config['device']
    baud = config['baud']
    listen_str = config['listen']
    resume_count = config['resume']
    send_delay_ms = config['delay']
    no_log_flag = config['no_log']
    send_igate = config['send']
    debug_flag = config['debug']
    mqtt_host_conf = config['mqtt_host']
    mqtt_port_conf = config['mqtt_port']
    mqtt_tls_conf = config['mqtt_tls']
    mqtt_user_conf = config['mqtt_user']
    mqtt_pass_conf = config['mqtt_pass']
    mqtt_forward_conf = config['mqtt_forward']
    telemetry_interval_minutes = config['telemetry_interval']
    aprs_callsign_conf = config['aprs_callsign']
    aprs_host_conf = config['aprs_host']
    aprs_port_conf = config['aprs_port']
    aprs_filter_conf = config['aprs_filter']

    # Newly loaded proxy settings
    proxy_enabled = config['proxy_enabled']
    proxy_port = config['proxy_port']

    DEBUG = debug_flag
    no_log = no_log_flag
    igate_callsign = send_igate

    mqtt_host = mqtt_host_conf
    mqtt_port = mqtt_port_conf
    mqtt_tls = mqtt_tls_conf
    mqtt_user = mqtt_user_conf
    mqtt_pass = mqtt_pass_conf

    mqtt_forward = mqtt_forward_conf

    aprs_enabled = (connection_type == 'aprs-is')
    if aprs_enabled:
        if not aprs_callsign_conf:
            print("Error: 'aprs_callsign' must be set when 'connection_type' is 'aprs-is'.", file=sys.stderr)
            exit(1)
        aprs_callsign = aprs_callsign_conf.upper()
        aprs_host = aprs_host_conf
        aprs_port = aprs_port_conf

    if ':' in listen_str:
        flask_ip, flask_port_str = listen_str.split(':',1)
        flask_port = int(flask_port_str)
    else:
        flask_ip = listen_str
        flask_port = 5001

    global packet_history
    if connection_type == 'serial':
        sanitized_device = device.replace('/', '_')
        filename = f"logs/aprs_packets_{connection_type}_{sanitized_device}.yaml"
    elif connection_type == 'aprs-is':
        filename = f"logs/aprs_packets_aprs-is.yaml"
    else:  # 'tcp'
        filename = f"logs/aprs_packets_{connection_type}_{host}_{port}.yaml"

    print(f"Using filename for logging: {filename}")

    packet_history = deque(maxlen=resume_count)

    if os.path.exists(filename) and resume_count > 0:
        try:
            with open(filename, 'r') as yf:
                docs = list(yaml.safe_load_all(yf))
                docs = docs[-resume_count:]
                for doc in docs:
                    if doc:
                        packet_history.append(doc)
            print(f"Loaded {len(packet_history)} pkts from {filename}")
        except Exception as e:
            print("Error loading from file:", e)

    telemetry_manager = TelemetryManager(filepath='config/telemetry.yaml')
    outgoing_aprs_queue = queue.Queue()

    all_data = telemetry_manager.get_telemetry_data()
    any_mqtt_enabled = any(
        ch_data.get('mqtt') for _call, val in all_data.items()
        for _ch, ch_data in val.get('channels',{}).items()
    )

    if any_mqtt_enabled or mqtt_forward:
        mqtt_manager = MqttManager(mqtt_host, mqtt_port, mqtt_tls, mqtt_user, mqtt_pass, telemetry_manager)
        for from_c, val in all_data.items():
            for ch_n, ch_d in val.get('channels',{}).items():
                if ch_d.get('mqtt'):
                    ts = ch_d['topic_state']
                    tc = ch_d['topic_cmd']
                    mqtt_manager.add_channel(from_c, ch_n, ts, tc)
    else:
        mqtt_manager = None

    for fc in telemetry_manager.get_telemetry_data():
        v = telemetry_manager.state[fc]
        has_eqns = any(
            1 <= ch <= 5 and 'eqns' in ch_data
            for ch, ch_data in v['channels'].items()
        )
        msgs = telemetry_manager.generate_telemetry_messages(fc, {
            'parameter_changed': True,
            'unit_changed': True,
            'value_changed': True,
            'eqns_changed': has_eqns,
            'mqtt_changed': False
        })
        for m in msgs:
            outgoing_aprs_queue.put(m)

    # If proxy is enabled, initialise proxy_clients set and start the proxy server
    if proxy_enabled:
        proxy_clients = set()
        start_proxy_server(proxy_port)
    else:
        proxy_clients = None

    if connection_type != 'aprs-is':
        def connect_and_receive():
            global tnc_connection
            while True:
                try:
                    if connection_type == 'tcp':
                        print(f"Connecting to TNC {host}:{port}...")
                        tnc_connection = TNCConnection('tcp', host=host, port=port, timeout=5)
                    elif connection_type == 'serial':
                        print(f"Connecting to TNC Serial Device {device} at {baud} baud...")
                        tnc_connection = TNCConnection('serial', device=device, baud=baud, timeout=1)
                    print("Connected to TNC.")
                    start_receive_thread(tnc_connection, connection_type, config, filename, no_log, igate_callsign, telemetry_manager)
                    break
                except Exception as e:
                    print(f"Error connecting TNC: {e}")
                    print("Retrying in 5 seconds...")
                    time.sleep(5)

        tnc_thread = threading.Thread(target=connect_and_receive, daemon=True)
        tnc_thread.start()
    else:
        tnc_connection = None
        print("Connection type is 'aprs-is'; TNC connection is skipped.")

    # Now that Socket.IO is about to be started, initialise it with the Flask app.
    socketio.init_app(app, async_mode='eventlet')
    # Set our global socketio_instance for log emission in LogTee.
    global socketio_instance
    socketio_instance = socketio

    # Now reassign sys.stdout and sys.stderr to our Tee so that future prints are logged and emitted.
    sys.stdout = LogTee(log_file)
    sys.stderr = LogTee(log_file)

    print("LogTee now active");

    if aprs_enabled:
        eventlet.spawn_n(connect_aprs_is)
        eventlet.spawn_n(receive_aprs_is_data)

    send_thread = threading.Thread(target=send_frames, args=(send_delay_ms,), daemon=True)
    send_thread.start()

    socketio.start_background_task(telemetry_background_task, telemetry_manager, telemetry_interval_minutes)

    print(f"Listening on {flask_ip}:{flask_port} ...")
    socketio.run(app, host=flask_ip, port=flask_port)

if __name__=="__main__":
    main()
