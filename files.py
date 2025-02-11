#!/usr/bin/env python3
"""
KISS File Transfer CLI (sender/receiver)
-----------------------------------------
This script implements a simple KISS–framed file transfer system over TCP
(or serial). It builds packets that contain an AX.25 header plus an “info”
field (including file metadata) concatenated with a binary payload.
If compression is enabled the file is compressed (using zlib.compress, which
produces an standard zlib deflate stream) and then split into chunks.
"""

import argparse
import hashlib
import os
import random
import socket
import sys
import threading
import time
import zlib
from math import ceil
from queue import Queue, Empty
import logging

# Configure logging with timestamps for every entry.
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Set DEBUG = False for verbose debugging.
DEBUG = False

#############################
# KISS / AX.25 Utility Functions
#############################

KISS_FLAG = 0xC0
KISS_CMD_DATA = 0x00

def escape_data(data: bytes) -> bytes:
    """Escape any KISS special bytes so that framing is preserved."""
    out = bytearray()
    for b in data:
        if b == KISS_FLAG:
            out.extend([0xDB, 0xDC])
        elif b == 0xDB:
            out.extend([0xDB, 0xDD])
        else:
            out.append(b)
    return bytes(out)

def unescape_data(data: bytes) -> bytes:
    """Reverse the KISS escape to recover the original bytes."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0xDB and i+1 < len(data):
            nxt = data[i+1]
            if nxt == 0xDC:
                out.append(KISS_FLAG)
                i += 2
                continue
            elif nxt == 0xDD:
                out.append(0xDB)
                i += 2
                continue
        out.append(b)
        i += 1
    return bytes(out)

def build_kiss_frame(packet: bytes) -> bytes:
    """Build a KISS frame from raw packet bytes."""
    escaped = escape_data(packet)
    return bytes([KISS_FLAG, KISS_CMD_DATA]) + escaped + bytes([KISS_FLAG])

def extract_kiss_frames(data: bytes) -> (list, bytes):
    """
    Given a buffer of bytes, extract complete KISS frames.
    Returns a tuple of (list of complete frames, remaining bytes).
    """
    frames = []
    while True:
        try:
            start = data.index(KISS_FLAG)
        except ValueError:
            break
        try:
            end = data.index(KISS_FLAG, start + 1)
        except ValueError:
            break
        frame = data[start:end+1]
        frames.append(frame)
        data = data[end+1:]
    return frames, data

def pad_callsign(cs: str) -> str:
    """Pad and uppercase a callsign to 9 characters."""
    return cs.upper().ljust(9)

def generate_file_id() -> str:
    """Generate a simple two‐character file ID."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return random.choice(chars) + random.choice(chars)

def encode_ax25_address(callsign: str, is_last: bool) -> bytes:
    """Encode an AX.25 address field for the given callsign."""
    call = callsign.upper().split('-')[0]
    call = call.ljust(6)[:6]
    addr = bytearray(7)
    for i in range(6):
        addr[i] = ord(call[i]) << 1
    addr[6] = 0x60
    if is_last:
        addr[6] |= 0x01
    return bytes(addr)

def build_ax25_header(source: str, destination: str) -> bytes:
    """Build an AX.25 header using the source and destination callsigns."""
    dest = encode_ax25_address(destination, is_last=False)
    src  = encode_ax25_address(source, is_last=True)
    return dest + src + bytes([0x03]) + bytes([0xF0])

#############################
# Packet Building & Parsing
#############################

# Each payload chunk is CHUNK_SIZE bytes.
# Reduced by 4 bytes (from 209 to 205) to offset the increase in the info field length.
CHUNK_SIZE = 205

def build_packet(sender: str, receiver: str, seq: int, total_data_packets: int,
                 payload: bytes, file_id: str, burst_to: int) -> bytes:
    """
    Build a packet.
    For seq==1 (header) the info field is built as:
      "SENDER>RECEIVER:FILEID:0001{burst_to_hex}/{total_hex}:"
    For data packets (seq>=2) it is:
      "SENDER>RECEIVER:FILEID:{seq_hex}{burst_to_hex}:"
    """
    s_str = pad_callsign(sender)
    r_str = pad_callsign(receiver)
    if seq == 1:
        total_hex = format(total_data_packets, '04X')
        info = f"{s_str}>{r_str}:{file_id}:0001{format(burst_to, '04X')}/{total_hex}:"
    else:
        info = f"{s_str}>{r_str}:{file_id}:{format(seq, '04X')}{format(burst_to, '04X')}:"
    info_bytes = info.encode('utf-8')
    ax25 = build_ax25_header(sender, receiver)
    return ax25 + info_bytes + payload

def parse_packet(packet: bytes):
    """
    Parse an unescaped packet.
    
    For ACK frames, if "ACK:" is found in the beginning of the info field,
    decode the frame as an ACK.
    
    For data frames, we know the info field has a fixed length:
      • For header packets (seq==1), the info field ends with the final colon.
      • For data packets (seq>=2) it is fixed at 32 bytes.
    The remainder is the binary payload.
    
    Returns a dictionary with keys:
      For data packets: "type", "sender", "receiver", "file_id", "seq",
                        "burst_to", "total" (if provided), "payload", "raw_info".
      For ACK frames: "type", "ack", "raw_info".
    """
    if DEBUG:
        logging.debug("DEBUG: parse_packet: Raw packet bytes: " + packet.hex())
    if len(packet) < 16:
        if DEBUG:
            logging.debug("DEBUG: Packet too short (<16 bytes).")
        return None
    ax25 = packet[:16]
    info_and_payload = packet[16:]
    
    try:
        info_prefix = info_and_payload[:50].decode('utf-8', errors='replace')
    except Exception as e:
        info_prefix = ""
    if "ACK:" in info_prefix:
        full_info = info_and_payload.decode('utf-8', errors='replace')
        if DEBUG:
            logging.debug("DEBUG: Detected ACK frame; full_info: " + full_info)
        parts = full_info.split("ACK:")
        if len(parts) >= 2:
            ack_val = parts[1].strip().strip(':')
            return {"type": "ack", "ack": ack_val, "raw_info": full_info}
    
    # Updated minimum length for info field (data packets now require 32 bytes)
    if len(info_and_payload) < 32:
        return None

    # Header packet: info field starts with bytes 23-27 equal to b'0001'
    if info_and_payload[23:27] == b'0001':
        try:
            # Look for the terminating colon that ends the info field (starting at index 27).
            end_idx = info_and_payload.index(b':', 27) + 1
        except ValueError:
            if DEBUG:
                logging.debug("DEBUG: No terminating colon found in header info field.")
            return None
        info_field = info_and_payload[:end_idx]
        payload = info_and_payload[end_idx:]
    else:
        # Data packet: info field is fixed to 32 bytes.
        info_field = info_and_payload[:32]
        payload = info_and_payload[32:]
    try:
        info_str = info_field.decode('utf-8', errors='replace')
    except Exception as e:
        if DEBUG:
            logging.debug("DEBUG: Exception decoding info_field: " + str(e))
        return None
    if DEBUG:
        logging.debug("DEBUG: Decoded info field: " + info_str)
    parts = info_str.split(':')
    if DEBUG:
        logging.debug("DEBUG: Info field parts: " + str(parts))
    if len(parts) < 4:
        if DEBUG:
            logging.debug("DEBUG: Expected at least 4 parts, got: " + str(parts))
        return None
    s_r = parts[0].split('>')
    if len(s_r) != 2:
        if DEBUG:
            logging.debug("DEBUG: Could not split sender and receiver from: " + parts[0])
        return None
    sender = s_r[0].strip()
    receiver = s_r[1].strip()
    file_id = parts[1].strip()
    seq_burst = parts[2].strip()
    total = None
    if '/' in seq_burst:
        seq_burst_part, total_str = seq_burst.split('/')
        if len(seq_burst_part) != 8:
            if DEBUG:
                logging.debug("DEBUG: Header packet seq/burst part not 8 digits: " + seq_burst_part)
            return None
        seq = 1
        try:
            burst_to = int(seq_burst_part[4:], 16)
        except Exception as e:
            if DEBUG:
                logging.debug("DEBUG: Exception converting burst_to: " + str(e))
            return None
        try:
            total = int(total_str, 16)
        except Exception as e:
            if DEBUG:
                logging.debug("DEBUG: Exception converting total: " + str(e))
            total = None
    else:
        if len(seq_burst) != 8:
            if DEBUG:
                logging.debug("DEBUG: Data packet seq/burst part not 8 digits: " + seq_burst)
            return None
        try:
            seq = int(seq_burst[:4], 16)
            burst_to = int(seq_burst[4:], 16)
        except Exception as e:
            if DEBUG:
                logging.debug("DEBUG: Exception converting seq or burst: " + str(e))
            return None
    if DEBUG:
        logging.debug(f"Logging: Packet seq={seq} has burst_to={burst_to}")
    return {"type": "data",
            "sender": sender,
            "receiver": receiver,
            "file_id": file_id,
            "seq": seq,
            "burst_to": burst_to,
            "total": total,
            "payload": payload,
            "raw_info": info_str}

#############################
# Connection Classes
#############################

class KISSConnectionBase:
    def send_frame(self, frame: bytes):
        raise NotImplementedError
    def recv_data(self, timeout: float = 0.1) -> bytes:
        raise NotImplementedError
    def close(self):
        raise NotImplementedError

class TCPKISSConnection(KISSConnectionBase):
    def __init__(self, host: str, port: int, is_server: bool):
        self.is_server = is_server
        if is_server:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((host, port))
            self.sock.listen(1)
            logging.info(f"[TCP Server] Listening on {host}:{port} …")
            self.conn, addr = self.sock.accept()
            logging.info(f"[TCP Server] Connection from {addr}")
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logging.info(f"[TCP Client] Connecting to {host}:{port} …")
            self.sock.connect((host, port))
            self.conn = self.sock
            logging.info(f"[TCP Client] Connected to {host}:{port}")
        self.lock = threading.Lock()
        self.recv_buffer = bytearray()
    def send_frame(self, frame: bytes):
        with self.lock:
            self.conn.sendall(frame)
    def recv_data(self, timeout: float = 0.1) -> bytes:
        self.conn.settimeout(timeout)
        try:
            data = self.conn.recv(1024)
            return data
        except socket.timeout:
            return b''
        except Exception as e:
            logging.error("TCP recv error: " + str(e))
            return b''
    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        if self.is_server and self.sock:
            self.sock.close()

class SerialKISSConnection(KISSConnectionBase):
    def __init__(self, port: str, baud: int):
        try:
            import serial
        except ImportError:
            logging.error("pyserial module not found – please install pyserial.")
            sys.exit(1)
        self.ser = serial.Serial(port, baud, timeout=0.1)
        logging.info(f"[Serial] Opened serial port {port} at {baud} baud")
        self.lock = threading.Lock()
        self.recv_buffer = bytearray()
    def send_frame(self, frame: bytes):
        with self.lock:
            self.ser.write(frame)
    def recv_data(self, timeout: float = 0.1) -> bytes:
        return self.ser.read(1024)
    def close(self):
        self.ser.close()

#############################
# Frame Reader Thread
#############################

class FrameReader(threading.Thread):
    """
    Continuously reads from the connection, extracts complete KISS frames,
    unescapes the data, and places the resulting packet into a Queue.
    """
    def __init__(self, conn: KISSConnectionBase, queue: Queue):
        super().__init__(daemon=True)
        self.conn = conn
        self.queue = queue
        self.running = True
        self.buffer = bytearray()
    def run(self):
        while self.running:
            data = self.conn.recv_data()
            if data:
                self.buffer.extend(data)
                frames, self.buffer = extract_kiss_frames(self.buffer)
                for f in frames:
                    if f[0] == KISS_FLAG and f[-1] == KISS_FLAG:
                        inner = f[2:-1]  # Remove starting flag & command and ending flag.
                        unescaped = unescape_data(inner)
                        self.queue.put(unescaped)
            else:
                time.sleep(0.01)
    def stop(self):
        self.running = False

#############################
# Sender Main Function
#############################

def sender_main(args):
    if not os.path.isfile(args.file):
        logging.error(f"File: {args.file} not found.")
        sys.exit(1)
    with open(args.file, 'rb') as f:
        file_data = f.read()
    original_size = len(file_data)
    if args.compress:
        try:
            final_data = zlib.compress(file_data, level=9)
        except Exception as e:
            logging.error("Compression error: " + str(e))
            sys.exit(1)
    else:
        final_data = file_data
    compressed_size = len(final_data)
    md5_hash = hashlib.md5(file_data).hexdigest()
    file_id = generate_file_id()
    # Compute number of data packets (excluding header)
    data_packet_count = ceil(len(final_data) / CHUNK_SIZE)
    total_including_header = data_packet_count + 1
    # Header now includes two extra fields at the start: timeout-seconds and timeout-retries
    header_str = f"{args.timeout_seconds}|{args.timeout_retries}|{os.path.basename(args.file)}|{original_size}|{compressed_size}|{md5_hash}|{file_id}|{'1' if args.compress else '0'}|{total_including_header}"
    header_payload = header_str.encode('utf-8')
    # Log each header field if debug is enabled.
    if DEBUG:
        field_names = ["timeout_seconds", "timeout_retries", "filename", "original_size", "compressed_size", "md5_hash", "file_id", "compress_flag", "total_packets"]
        for name, value in zip(field_names, header_str.split("|")):
            logging.debug(f"Sending header field {name}: {value}")
    # Build list of chunks: header (packet 1) plus data packets.
    chunks = [header_payload]
    for i in range(0, len(final_data), CHUNK_SIZE):
        chunks.append(final_data[i:i+CHUNK_SIZE])
    total_packets = len(chunks)
    logging.info(f"File: {args.file} ({original_size} bytes)")
    logging.info(f"Compressed to {compressed_size} bytes, split into {data_packet_count} data packets (total packets including header: {total_including_header})")
    logging.info(f"MD5: {md5_hash}  File ID: {file_id}")

    # --- NEW: Use only the actual file data for stats (exclude header) ---
    total_bytes_to_send = len(final_data)
    overall_start = time.time()
    total_bytes_sent = 0
    total_retries = 0
    burst_retries = 0

    # Allowed window sizes: 1, 2, 4, 8, 10; starting at 4.
    allowed_windows = [1, 2, 4, 6, 8, 10]
    if args.window_size != "auto":
        try:
            win_val = int(args.window_size)
            if win_val in allowed_windows:
                current_window_index = allowed_windows.index(win_val)
            else:
                logging.info(f"Provided window size {win_val} is not allowed. Defaulting to 4.")
                current_window_index = allowed_windows.index(4)
        except ValueError:
            logging.info("Invalid window size argument. Defaulting to 4.")
            current_window_index = allowed_windows.index(4)
    else:
        current_window_index = allowed_windows.index(4)  # default if auto
    successful_burst_count = 0  # count of consecutive fully-acknowledged bursts at current window size

    # Open the connection.
    if args.connection == "tcp":
        conn = TCPKISSConnection(args.host, args.port, is_server=False)
    else:
        conn = SerialKISSConnection(args.serial_port, args.baud)
    frame_q = Queue()
    reader = FrameReader(conn, frame_q)
    reader.start()
    # Sender state: header is seq==1; data packets: seq==2,3,...
    state = {"current_packet": 1, "total_packets": total_including_header}
    def flush_queue():
        while not frame_q.empty():
            try:
                frame_q.get_nowait()
            except Empty:
                break

    # --- Modified send_packet: return only actual file data length ---
    def send_packet(seq):
        if seq == 1:
            burst_to = 1
            # Send header as usual but do not count its bytes.
            pkt = build_packet(args.my_callsign, args.receiver_callsign,
                               seq, total_including_header - 1,
                               chunks[seq-1], file_id, burst_to)
            frame = build_kiss_frame(pkt)
            conn.send_frame(frame)
            logging.info(f"Sent packet seq={seq}, burst_to={burst_to}.")
            return 0
        else:
            burst_to = min(total_including_header, state["current_packet"] + allowed_windows[current_window_index] - 1)
            pkt = build_packet(args.my_callsign, args.receiver_callsign,
                               seq, total_including_header - 1,
                               chunks[seq-1], file_id, burst_to)
            frame = build_kiss_frame(pkt)
            conn.send_frame(frame)
            logging.info(f"Sent packet seq={seq}, burst_to={burst_to}.")
            return len(chunks[seq-1])
    
    # wait_for_ack waits for an ACK, using a dynamic timeout.
    # Added parameter is_header (default False). When True, on each timeout the header packet is re‑sent.
    def wait_for_ack(num_packets, is_header=False):
        nonlocal total_retries, burst_retries
        retries = 0
        current_timeout = num_packets * 1.5 + args.timeout_seconds
        while retries < args.timeout_retries:
            if is_header and retries > 0:
                logging.info(f"Resending header packet (retry {retries}/{args.timeout_retries}).")
                send_packet(1)
            try:
                pkt = frame_q.get(timeout=current_timeout)
            except Empty:
                retries += 1
                total_retries += 1
                burst_retries += 1
                logging.info(f"Timeout waiting for ACK (retry {retries}/{args.timeout_retries}, timeout was {current_timeout:.2f}s).")
                current_timeout = args.timeout_seconds * (1.5 ** retries)
                continue
            parsed = parse_packet(pkt)
            if parsed and parsed.get("type") == "ack":
                return parsed["ack"]
        return None

    flush_queue()
    # Send header packet (seq 1) and wait for ACK "0001"
    logging.info("Sending header packet (seq=1) …")
    header_len = send_packet(1)
    total_bytes_sent += header_len  # header not counted
    ack_val = wait_for_ack(1, is_header=True)
    if ack_val is None:
        logging.info("No ACK received for header after maximum retries. Giving up on transfer.")
        reader.stop()
        conn.close()
        sys.exit(1)
    logging.info(f"Received ACK: {ack_val}")
    try:
        ack_int = int(ack_val, 16)
    except Exception:
        ack_int = 0
    while ack_int != 1:
        logging.info(f"Unexpected header ACK {ack_val}; waiting for correct ACK …")
        ack_val = wait_for_ack(1, is_header=True)
        if ack_val is None:
            logging.info("No correct header ACK received after maximum retries. Giving up on transfer.")
            reader.stop()
            conn.close()
            sys.exit(1)
        try:
            ack_int = int(ack_val, 16)
        except Exception:
            continue
    state["current_packet"] = ack_int + 1
    logging.info("Header ACK received (0001); proceeding with data packets …")
    # Main loop for data packets using dynamic sliding window.
    while state["current_packet"] <= total_including_header:
        flush_queue()
        start_seq = state["current_packet"]
        current_window = allowed_windows[current_window_index]
        end_seq = min(total_including_header, start_seq + current_window - 1)
        logging.info(f"Sending burst: packets {start_seq} to {end_seq} (window size {current_window}) …")
        burst_start = time.time()
        burst_bytes = 0
        burst_retries = 0
        for seq in range(start_seq, end_seq + 1):
            pkt_len = send_packet(seq)
            burst_bytes += pkt_len
            total_bytes_sent += pkt_len
            time.sleep(0.005)
        burst_count = end_seq - start_seq + 1
        expected_ack = end_seq + 1
        ack_val = wait_for_ack(burst_count)
        if ack_val is None:
            logging.info("No ACK received after maximum retries. Giving up on transfer.")
            break
        logging.info(f"Received ACK: {ack_val}")
        try:
            if '-' in ack_val:
                ack_int = int(ack_val.split('-')[1], 16) + 1
            else:
                ack_int = int(ack_val, 16) + 1
        except Exception:
            ack_int = state["current_packet"] + 1
        # Adjust sliding window:
        if ack_int == expected_ack:
            successful_burst_count += 1
            logging.info("All packets in burst acknowledged.")
            if successful_burst_count >= 2 and current_window_index < len(allowed_windows) - 1:
                current_window_index += 1
                successful_burst_count = 0
                logging.info(f"Increasing window size to {allowed_windows[current_window_index]}")
            else:
                logging.info(f"Window remains at {allowed_windows[current_window_index]}")
        else:
            logging.info(f"Not all packets acknowledged. Expected ACK: {expected_ack}, received ACK: {ack_int}")
            if current_window_index > 0:
                current_window_index -= 1
                successful_burst_count = 0
                logging.info(f"Reducing window size to {allowed_windows[current_window_index]}")
            else:
                logging.info("Window size is at minimum (1).")
        if ack_int <= state["current_packet"]:
            logging.info("Stale ACK received; waiting for next ACK …")
            continue
        state["current_packet"] = ack_int
        logging.info(f"Updated current_packet to {state['current_packet']}.")

        # --- Stats for this burst ---
        burst_end = time.time()
        burst_duration = burst_end - burst_start
        burst_rate = burst_bytes / burst_duration if burst_duration > 0 else 0
        overall_elapsed = time.time() - overall_start
        overall_rate = total_bytes_sent / overall_elapsed if overall_elapsed > 0 else 0
        progress = (total_bytes_sent / total_bytes_to_send) * 100
        eta = (total_bytes_to_send - total_bytes_sent) / overall_rate if overall_rate > 0 else float('inf')
        logging.info("--- Stats ---")
        logging.info(f"Previous burst: {burst_bytes} bytes in {burst_duration:.2f}s ({burst_rate:.2f} bytes/s)")
        logging.info(f"Overall: {total_bytes_sent}/{total_bytes_to_send} bytes ({progress:.2f}%), elapsed: {overall_elapsed:.2f}s, ETA: {eta:.2f}s")
        logging.info(f"Overall bytes/sec: {overall_rate:.2f} bytes/s, Burst retries: {burst_retries}, Total retries: {total_retries}")
        logging.info("--------------")
    overall_elapsed = time.time() - overall_start
    overall_rate = total_bytes_sent / overall_elapsed if overall_elapsed > 0 else 0
    logging.info("File transfer complete.")
    logging.info("=== Final Summary ===")
    logging.info(f"Total bytes sent: {total_bytes_sent} bytes in {overall_elapsed:.2f}s ({overall_rate:.2f} bytes/s).")
    logging.info(f"Total retries: {total_retries}.")
    logging.info("=====================")
    reader.stop()
    conn.close()

#############################
# Receiver Main Function
#############################

# --- Modified cumulative ACK function ---
def compute_cumulative_ack(transfer):
    """
    Compute the latest contiguous sequence range.
    If only the header (seq==1) is received, return "0001".
    Otherwise, assume header is present and return "0001-XXXX" where XXXX is the highest
    contiguous data packet number received (in 4-digit hex).
    """
    # Header is always received (seq 1)
    contiguous = 1
    # Look at data packets (seq>=2)
    data_keys = sorted([k for k in transfer["packets"].keys() if k >= 2])
    if not data_keys:
         return "0001"
    for num in range(2, max(data_keys)+2):
         if num in transfer["packets"]:
              contiguous = num
         else:
              break
    if contiguous == 1:
         return "0001"
    else:
         return f"0001-{contiguous:04X}"

def receiver_main(args):
    if args.connection == "tcp":
        conn = TCPKISSConnection(args.host, args.port, is_server=True)
    else:
        conn = SerialKISSConnection(args.serial_port, args.baud)
    frame_q = Queue()
    reader = FrameReader(conn, frame_q)
    reader.start()
    logging.info(f"Receiver started. My callsign: {args.my_callsign.upper()}")
    transfers = {}  # key: file_id

    def send_ack(my_callsign, remote, file_id, ack_str):
        s_str = pad_callsign(my_callsign)
        r_str = pad_callsign(remote)
        info = f"{s_str}>{r_str}:{file_id}:ACK:{ack_str}"
        ack_pkt = build_ax25_header(my_callsign, remote) + info.encode('utf-8')
        frame = build_kiss_frame(ack_pkt)
        conn.send_frame(frame)
        logging.info(f"Sent ACK: {ack_str} for file {file_id}")

    # Main receiver loop.
    while True:
        try:
            pkt = frame_q.get(timeout=0.5)
        except Empty:
            now = time.time()
            # --- Modified retry logic using exponential back-off ---
            for fid in list(transfers.keys()):
                transfer = transfers[fid]
                last_ack_sent = transfer.get("last_ack_sent", 0)
                last_received = transfer.get("last_received", 0)
                # Use the later of the last ACK sent or the last packet received
                last_event = max(last_ack_sent, last_received)
                if "retry_interval" not in transfer:
                    transfer["retry_interval"] = transfer["timeout_seconds"]
                if now - last_event >= transfer["retry_interval"]:
                    if transfer.get("retry_count", 0) < transfer["timeout_retries"]:
                        ack_range = compute_cumulative_ack(transfer)
                        send_ack(args.my_callsign, transfer["sender"], fid, ack_range)
                        transfer["last_ack_sent"] = now
                        transfer["retry_count"] = transfer.get("retry_count", 0) + 1
                        logging.info(f"Resent ACK {ack_range} for file {fid} due to inactivity (retry {transfer['retry_count']}/{transfer['timeout_retries']}, interval {transfer['retry_interval']:.2f}s).")
                        transfer["retry_interval"] *= 1.5
                    else:
                        logging.info(f"Giving up on transfer {fid} after {transfer['timeout_retries']} ACK retries due to inactivity.")
                        del transfers[fid]
            continue

        parsed = parse_packet(pkt)
        if parsed is None:
            logging.info("Could not parse packet.")
            if DEBUG:
                logging.debug("DEBUG: Raw packet bytes: " + pkt.hex())
            continue
        if parsed.get("type") == "ack":
            logging.info("Received an ACK packet (ignored on receiver).")
            continue

        seq = parsed.get("seq")
        file_id = parsed.get("file_id")
        sender = parsed.get("sender")
        rec = parsed.get("receiver")
        logging.info(f"Received data packet: seq={seq}, file_id={file_id}, burst_to={parsed.get('burst_to')}, sender={sender}, receiver={rec}")
        local_cs = args.my_callsign.strip().upper()
        if rec.strip().upper() != local_cs:
            logging.info(f"Packet intended for {rec.strip().upper()}, not me ({local_cs}). Ignoring.")
            continue

        if file_id not in transfers:
            if seq != 1:
                logging.info(f"Received non-header packet (seq={seq}) for unknown transfer {file_id}. Ignoring.")
                continue
            header_payload = parsed.get("payload")
            try:
                header_info = header_payload.decode('utf-8', errors='replace')
                parts = header_info.split("|")
                if len(parts) < 9:
                    logging.info("Invalid header info – ignoring transfer.")
                    continue
                # If debug is enabled, log each header field received.
                if DEBUG:
                    field_names = ["timeout_seconds", "timeout_retries", "filename", "original_size", "compressed_size", "md5_hash", "file_id", "compress_flag", "total_packets"]
                    for name, value in zip(field_names, parts):
                        logging.debug(f"Received header field {name}: {value}")
                transfer_timeout_seconds = float(parts[0])
                transfer_timeout_retries = int(parts[1])
                filename = parts[2]
                orig_size = int(parts[3])
                comp_size = int(parts[4])
                md5_hash = parts[5]
                file_id = parts[6]
                comp_flag = parts[7]
                total_packets = int(parts[8])
                compress = (comp_flag == "1")
            except Exception as e:
                logging.info("Error parsing header payload: " + str(e))
                continue
            # Initialize additional stats for the transfer.
            transfers[file_id] = {
                "sender": sender,
                "filename": filename,
                "orig_size": orig_size,
                "comp_size": comp_size,
                "md5": md5_hash,
                "compress": compress,
                "packets": {},
                "burst_to": parsed.get("burst_to"),  # Initially from header (likely 1)
                "last_received": time.time(),
                "last_ack_sent": time.time(),
                "retry_count": 0,
                # Set timeout values based on header fields
                "timeout_seconds": transfer_timeout_seconds,
                "timeout_retries": transfer_timeout_retries,
                "retry_interval": transfer_timeout_seconds,
                "total": total_packets,
                "start_time": time.time(),
                "bytes_received": 0,
                "duplicate_count": 0,
                "burst_bytes": 0,
                "last_burst_ack_time": time.time()
            }
            logging.info(f"Started transfer from {sender} (File: {filename}, ID: {file_id})")
            logging.info(f"Total packets required (including header): {total_packets}")
            send_ack(args.my_callsign, sender, file_id, "0001")
            continue

        transfer = transfers[file_id]
        # Update the transfer with the time of this received packet and reset the retry timer.
        transfer["last_received"] = time.time()
        transfer["retry_interval"] = transfer["timeout_seconds"]

        # --- New: Update burst_to from the latest packet if higher ---
        current_burst = parsed.get("burst_to")
        if current_burst and current_burst > transfer.get("burst_to", 0):
            transfer["burst_to"] = current_burst

        if seq in transfer["packets"]:
            transfer["duplicate_count"] = transfer.get("duplicate_count", 0) + 1
            logging.info(f"Duplicate packet seq {seq} received; duplicates so far: {transfer['duplicate_count']}.")
            continue
        transfer["packets"][seq] = parsed.get("payload")
        # Update bytes received and burst bytes.
        packet_length = len(parsed.get("payload"))
        transfer["bytes_received"] += packet_length
        transfer["burst_bytes"] = transfer.get("burst_bytes", 0) + packet_length

        # --- If this packet is at the burst boundary, send an immediate ACK and output stats ---
        if transfer.get("burst_to") is not None and seq == transfer.get("burst_to"):
            now = time.time()
            # Compute burst statistics using the time since the last burst boundary.
            burst_duration = now - transfer["last_burst_ack_time"]
            burst_bytes = transfer.get("burst_bytes", 0)
            burst_rate = burst_bytes / burst_duration if burst_duration > 0 else 0
            overall_elapsed = now - transfer["start_time"]
            overall_rate = transfer["bytes_received"] / overall_elapsed if overall_elapsed > 0 else 0
            progress = (transfer["bytes_received"] / transfer["comp_size"]) * 100
            eta = (transfer["comp_size"] - transfer["bytes_received"]) / overall_rate if overall_rate > 0 else float('inf')
            logging.info("--- Stats ---")
            logging.info(f"Previous burst: {burst_bytes} bytes in {burst_duration:.2f}s ({burst_rate:.2f} bytes/s)")
            logging.info(f"Overall: {transfer['bytes_received']}/{transfer['comp_size']} bytes ({progress:.2f}%), elapsed: {overall_elapsed:.2f}s, ETA: {eta:.2f}s")
            logging.info(f"Overall bytes/sec: {overall_rate:.2f} bytes/s, ACK retries: {transfer.get('retry_count', 0)}")
            logging.info("--------------")
            ack_range = compute_cumulative_ack(transfer)
            send_ack(args.my_callsign, sender, file_id, ack_range)
            transfer["last_ack_sent"] = now
            transfer["burst_bytes"] = 0
            transfer["last_burst_ack_time"] = now
            transfer["retry_count"] = 0
            transfer["retry_interval"] = transfer["timeout_seconds"]
        if transfer.get("total") is not None and len(transfer["packets"]) == transfer["total"] - 1:
            overall_elapsed = time.time() - transfer["start_time"]
            overall_rate = transfer["bytes_received"] / overall_elapsed if overall_elapsed > 0 else 0
            logging.info(f"=== Receiver Final Summary for file {file_id} ===")
            logging.info(f"Total bytes received: {transfer['bytes_received']} bytes in {overall_elapsed:.2f}s ({overall_rate:.2f} bytes/s), Duplicates: {transfer.get('duplicate_count', 0)}.")
            logging.info("===============================================")
            logging.info(f"Transfer complete for file {file_id}. Reassembling file …")
            data_parts = []
            complete = True
            for seq_num in range(2, transfer["total"] + 1):
                if seq_num not in transfer["packets"]:
                    logging.info(f"Missing packet {seq_num} – cannot reassemble.")
                    complete = False
                    break
                data_parts.append(transfer["packets"][seq_num])
            if not complete:
                continue
            full_data = b"".join(data_parts)
            if transfer["compress"]:
                try:
                    full_data = zlib.decompress(full_data)
                except zlib.error:
                    try:
                        full_data = zlib.decompress(full_data, -zlib.MAX_WBITS)
                    except Exception as e:
                        logging.info("Decompression error: " + str(e))
                        continue
                except Exception as e:
                    logging.info("Decompression error: " + str(e))
                    continue
            computed_md5 = hashlib.md5(full_data).hexdigest()
            if computed_md5 == transfer["md5"]:
                logging.info("Checksum OK.")
            else:
                logging.info(f"Checksum mismatch! (Expected: {transfer['md5']}, Got: {computed_md5})")
            outname = transfer["filename"]
            base, ext = os.path.splitext(outname)
            cnt = 1
            while os.path.exists(outname):
                outname = f"{base}_{cnt}{ext}"
                cnt += 1
            with open(outname, 'wb') as f:
                f.write(full_data)
            logging.info(f"Saved received file as {outname}")
            del transfers[file_id]
            # --- NEW: If the --one-file flag is set, exit receiver mode after one file ---
            if args.one_file:
                logging.info("Received one file successfully. Exiting receiver mode as --one-file flag is set.")
                break
    reader.stop()
    conn.close()

#############################
# Main & Argument Parsing
#############################

def main():
    global DEBUG
    parser = argparse.ArgumentParser(description="KISS File Transfer CLI (sender/receiver).")
    parser.add_argument('--role', choices=['sender', 'receiver'], required=True,
                        help="Role: sender or receiver")
    parser.add_argument('--my-callsign', required=True,
                        help="Your callsign")
    parser.add_argument('--receiver-callsign',
                        help="Receiver callsign (required if sender)")
    parser.add_argument('--window-size', default="4",
                        help="Window (burst) size as an integer, or 'auto'")
    parser.add_argument('--connection', choices=['tcp', 'serial'], default='tcp',
                        help="Connection type: tcp or serial")
    parser.add_argument('--debug', action='store_true', help="Enable debug output")
    parser.add_argument('--host', default='127.0.0.1',
                        help="TCP host (for sender: remote host; for receiver: bind address)")
    parser.add_argument('--port', type=int, default=9001,
                        help="TCP port")
    parser.add_argument('--serial-port', help="Serial port (e.g. COM3 or /dev/ttyUSB0)")
    parser.add_argument('--baud', type=int, default=115200,
                        help="Baud rate for serial")
    parser.add_argument('--file', help="File to send (required if sender)")
    parser.add_argument('--no-compress', dest='compress', action='store_false', help="Disable compression")
    # The following timeout arguments are only set on the sender side.
    parser.add_argument('--timeout-seconds', type=float, default=5.0,
                        help="Timeout in seconds (default 5 seconds) [Sender only]")
    parser.add_argument('--timeout-retries', type=int, default=5,
                        help="Number of timeout retries (default 5) [Sender only]")
    # --- NEW: Option to exit after one file is received (receiver mode only) ---
    parser.add_argument('--one-file', action='store_true',
                        help="Exit after successfully receiving one file (Receiver mode)")
    args = parser.parse_args()
    DEBUG = args.debug
    # If debug is enabled, set the logger level to DEBUG.
    if DEBUG:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.role == 'sender':
        if not args.receiver_callsign:
            logging.error("Error: --receiver-callsign is required in sender mode.")
            sys.exit(1)
        if args.connection == 'serial' and not args.serial_port:
            logging.error("Error: --serial-port is required for serial connection.")
            sys.exit(1)
        if args.connection == 'tcp' and not args.host:
            logging.error("Error: --host is required for TCP connection.")
            sys.exit(1)
        if not args.file:
            logging.error("Error: --file is required in sender mode.")
            sys.exit(1)
        sender_main(args)
    else:
        if args.connection == 'serial' and not args.serial_port:
            logging.error("Error: --serial-port is required for serial connection.")
            sys.exit(1)
        receiver_main(args)

if __name__ == '__main__':
    main()
