#!/usr/bin/env python3
"""
KISS File Transfer CLI (sender/receiver)
-----------------------------------------
This script implements a simple KISS–framed file transfer system over TCP
(or serial). It builds packets that contain an AX.25 header plus an “info”
field (including file metadata) concatenated with an binary payload.
If compression is enabled the file is compressed (using zlib.compress, which
produces a standard zlib deflate stream) and then split into chunks.
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

# Set DEBUG = True for verbose debugging.
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
        print("DEBUG: parse_packet: Raw packet bytes:", packet.hex())
    if len(packet) < 16:
        if DEBUG:
            print("DEBUG: Packet too short (<16 bytes).")
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
            print("DEBUG: Detected ACK frame; full_info:", full_info)
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
                print("DEBUG: No terminating colon found in header info field.")
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
            print("DEBUG: Exception decoding info_field:", e)
        return None
    if DEBUG:
        print("DEBUG: Decoded info field:", info_str)
    parts = info_str.split(':')
    if DEBUG:
        print("DEBUG: Info field parts:", parts)
    if len(parts) < 4:
        if DEBUG:
            print("DEBUG: Expected at least 4 parts, got:", parts)
        return None
    s_r = parts[0].split('>')
    if len(s_r) != 2:
        if DEBUG:
            print("DEBUG: Could not split sender and receiver from:", parts[0])
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
                print("DEBUG: Header packet seq/burst part not 8 digits:", seq_burst_part)
            return None
        seq = 1
        try:
            burst_to = int(seq_burst_part[4:], 16)
        except Exception as e:
            if DEBUG:
                print("DEBUG: Exception converting burst_to:", e)
            return None
        try:
            total = int(total_str, 16)
        except Exception as e:
            if DEBUG:
                print("DEBUG: Exception converting total:", e)
            total = None
    else:
        if len(seq_burst) != 8:
            if DEBUG:
                print("DEBUG: Data packet seq/burst part not 8 digits:", seq_burst)
            return None
        try:
            seq = int(seq_burst[:4], 16)
            burst_to = int(seq_burst[4:], 16)
        except Exception as e:
            if DEBUG:
                print("DEBUG: Exception converting seq or burst:", e)
            return None
    if DEBUG:
        print(f"Logging: Packet seq={seq} has burst_to={burst_to}")
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
            print(f"[TCP Server] Listening on {host}:{port} …")
            self.conn, addr = self.sock.accept()
            print(f"[TCP Server] Connection from {addr}")
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"[TCP Client] Connecting to {host}:{port} …")
            self.sock.connect((host, port))
            self.conn = self.sock
            print(f"[TCP Client] Connected to {host}:{port}")
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
            print("TCP recv error:", e)
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
            print("pyserial module not found – please install pyserial.")
            sys.exit(1)
        self.ser = serial.Serial(port, baud, timeout=0.1)
        print(f"[Serial] Opened serial port {port} at {baud} baud")
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
        print(f"File: {args.file} not found.")
        sys.exit(1)
    with open(args.file, 'rb') as f:
        file_data = f.read()
    original_size = len(file_data)
    if args.compress:
        try:
            final_data = zlib.compress(file_data, level=9)
        except Exception as e:
            print("Compression error:", e)
            sys.exit(1)
    else:
        final_data = file_data
    compressed_size = len(final_data)
    md5_hash = hashlib.md5(file_data).hexdigest()
    file_id = generate_file_id()
    # Compute number of data packets (excluding header)
    data_packet_count = ceil(len(final_data) / CHUNK_SIZE)
    total_including_header = data_packet_count + 1
    header_str = f"{os.path.basename(args.file)}|{original_size}|{compressed_size}|{md5_hash}|{file_id}|{'1' if args.compress else '0'}|{total_including_header}"
    header_payload = header_str.encode('utf-8')
    # Build list of chunks: header (packet 1) plus data packets.
    chunks = [header_payload]
    for i in range(0, len(final_data), CHUNK_SIZE):
        chunks.append(final_data[i:i+CHUNK_SIZE])
    total_packets = len(chunks)
    print(f"File: {args.file} ({original_size} bytes)")
    print(f"Compressed to {compressed_size} bytes, split into {data_packet_count} data packets (total packets including header: {total_including_header})")
    print(f"MD5: {md5_hash}  File ID: {file_id}")

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
                print(f"Provided window size {win_val} is not allowed. Defaulting to 4.")
                current_window_index = allowed_windows.index(4)
        except ValueError:
            print("Invalid window size argument. Defaulting to 4.")
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
            print(f"Sent packet seq={seq}, burst_to={burst_to}.")
            return 0
        else:
            burst_to = min(total_including_header, state["current_packet"] + allowed_windows[current_window_index] - 1)
            pkt = build_packet(args.my_callsign, args.receiver_callsign,
                               seq, total_including_header - 1,
                               chunks[seq-1], file_id, burst_to)
            frame = build_kiss_frame(pkt)
            conn.send_frame(frame)
            print(f"Sent packet seq={seq}, burst_to={burst_to}.")
            return len(chunks[seq-1])
    
    # wait_for_ack waits for an ACK, using dynamic timeout.
    def wait_for_ack(num_packets):
        nonlocal total_retries, burst_retries
        retries = 0
        while retries < 5:
            timeout_value = (num_packets * 1.5 + 5) if retries == 0 else 5
            try:
                pkt = frame_q.get(timeout=timeout_value)
            except Empty:
                retries += 1
                total_retries += 1
                burst_retries += 1
                print(f"Timeout waiting for ACK (retry {retries}/5).")
                continue
            parsed = parse_packet(pkt)
            if parsed and parsed.get("type") == "ack":
                return parsed["ack"]
        return None

    flush_queue()
    # Send header packet (seq 1) and wait for ACK "0001"
    print("Sending header packet (seq=1) …")
    header_len = send_packet(1)
    total_bytes_sent += header_len  # header not counted
    ack_val = wait_for_ack(1)
    if ack_val is None:
        print("No ACK received for header after 5 retries. Giving up on transfer.")
        reader.stop()
        conn.close()
        sys.exit(1)
    print(f"Received ACK: {ack_val}")
    try:
        ack_int = int(ack_val, 16)
    except Exception:
        ack_int = 0
    while ack_int != 1:
        print(f"Unexpected header ACK {ack_val}; waiting for correct ACK …")
        ack_val = wait_for_ack(1)
        if ack_val is None:
            print("No correct header ACK received after 5 retries. Giving up on transfer.")
            reader.stop()
            conn.close()
            sys.exit(1)
        try:
            ack_int = int(ack_val, 16)
        except Exception:
            continue
    state["current_packet"] = ack_int + 1
    print("Header ACK received (0001); proceeding with data packets …")
    # Main loop for data packets using dynamic sliding window.
    while state["current_packet"] <= total_including_header:
        flush_queue()
        start_seq = state["current_packet"]
        current_window = allowed_windows[current_window_index]
        end_seq = min(total_including_header, start_seq + current_window - 1)
        print(f"Sending burst: packets {start_seq} to {end_seq} (window size {current_window}) …")
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
            print("No ACK received after 5 retries. Giving up on transfer.")
            break
        print(f"Received ACK: {ack_val}")
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
            print("All packets in burst acknowledged.")
            if successful_burst_count >= 2 and current_window_index < len(allowed_windows) - 1:
                current_window_index += 1
                successful_burst_count = 0
                print(f"Increasing window size to {allowed_windows[current_window_index]}")
            else:
                print(f"Window remains at {allowed_windows[current_window_index]}")
        else:
            print(f"Not all packets acknowledged. Expected ACK: {expected_ack}, received ACK: {ack_int}")
            if current_window_index > 0:
                current_window_index -= 1
                successful_burst_count = 0
                print(f"Reducing window size to {allowed_windows[current_window_index]}")
            else:
                print("Window size is at minimum (1).")
        if ack_int <= state["current_packet"]:
            print("Stale ACK received; waiting for next ACK …")
            continue
        state["current_packet"] = ack_int
        print(f"Updated current_packet to {state['current_packet']}.")

        # --- Stats for this burst ---
        burst_end = time.time()
        burst_duration = burst_end - burst_start
        burst_rate = burst_bytes / burst_duration if burst_duration > 0 else 0
        overall_elapsed = time.time() - overall_start
        overall_rate = total_bytes_sent / overall_elapsed if overall_elapsed > 0 else 0
        progress = (total_bytes_sent / total_bytes_to_send) * 100
        eta = (total_bytes_to_send - total_bytes_sent) / overall_rate if overall_rate > 0 else float('inf')
        print(f"--- Stats ---")
        print(f"Previous burst: {burst_bytes} bytes in {burst_duration:.2f}s ({burst_rate:.2f} bytes/s)")
        print(f"Overall: {total_bytes_sent}/{total_bytes_to_send} bytes ({progress:.2f}%), elapsed: {overall_elapsed:.2f}s, ETA: {eta:.2f}s")
        print(f"Overall bytes/sec: {overall_rate:.2f} bytes/s, Burst retries: {burst_retries}, Total retries: {total_retries}")
        print(f"--------------")
    overall_elapsed = time.time() - overall_start
    overall_rate = total_bytes_sent / overall_elapsed if overall_elapsed > 0 else 0
    print("File transfer complete.")
    print(f"=== Final Summary ===")
    print(f"Total bytes sent: {total_bytes_sent} bytes in {overall_elapsed:.2f}s ({overall_rate:.2f} bytes/s).")
    print(f"Total retries: {total_retries}.")
    print("=====================")
    reader.stop()
    conn.close()

#############################
# Receiver Main Function
#############################

def receiver_main(args):
    if args.connection == "tcp":
        conn = TCPKISSConnection(args.host, args.port, is_server=True)
    else:
        conn = SerialKISSConnection(args.serial_port, args.baud)
    frame_q = Queue()
    reader = FrameReader(conn, frame_q)
    reader.start()
    print(f"Receiver started. My callsign: {args.my_callsign.upper()}")
    transfers = {}  # key: file_id

    def send_ack(my_callsign, remote, file_id, ack_str):
        s_str = pad_callsign(my_callsign)
        r_str = pad_callsign(remote)
        info = f"{s_str}>{r_str}:{file_id}:ACK:{ack_str}"
        ack_pkt = build_ax25_header(my_callsign, remote) + info.encode('utf-8')
        frame = build_kiss_frame(ack_pkt)
        conn.send_frame(frame)
        print(f"Sent ACK: {ack_str} for file {file_id}")

    def schedule_ack(transfer, sender, file_id):
        if transfer.get("ack_timer") is not None:
            transfer["ack_timer"].cancel()
        def ack_timeout():
            ack_str = compute_cumulative_ack(transfer)
            send_ack(args.my_callsign, sender, file_id, ack_str)
            transfer["last_ack_sent"] = time.time()
            transfer["ack_timer"] = None
        t = threading.Timer(2.0, ack_timeout)
        transfer["ack_timer"] = t
        t.start()

    def compute_cumulative_ack(transfer):
        data_keys = sorted([k for k in transfer["packets"].keys() if k >= 2])
        if not data_keys:
            return "0002"
        contiguous = 2
        for num in range(2, max(data_keys)+2):
            if num in transfer["packets"]:
                contiguous = num
            else:
                break
        if contiguous == 2:
            return "0002"
        else:
            return f"0002-{contiguous:04X}"

    # Main receiver loop.
    while True:
        try:
            pkt = frame_q.get(timeout=0.5)
        except Empty:
            now = time.time()
            # For each active transfer, resend an ACK if 10 seconds have passed
            # since the last ACK was sent and since the last new packet was received.
            for fid in list(transfers.keys()):
                transfer = transfers[fid]
                last_ack_sent = transfer.get("last_ack_sent", 0)
                last_received = transfer.get("last_received", 0)
                if now - last_ack_sent >= 10 and now - last_received >= 10:
                    if transfer.get("retry_count", 0) < 5:
                        ack_range = compute_cumulative_ack(transfer)
                        send_ack(args.my_callsign, transfer["sender"], fid, ack_range)
                        transfer["last_ack_sent"] = now
                        transfer["retry_count"] = transfer.get("retry_count", 0) + 1
                        print(f"Resent ACK {ack_range} for file {fid} due to 10s inactivity (retry {transfer['retry_count']}/5).")
                    else:
                        print(f"Giving up on transfer {fid} after 5 ACK retries due to inactivity.")
                        del transfers[fid]
            continue

        parsed = parse_packet(pkt)
        if parsed is None:
            print("Could not parse packet.")
            if DEBUG:
                print("DEBUG: Raw packet bytes:", pkt.hex())
            continue
        if parsed.get("type") == "ack":
            print("Received an ACK packet (ignored on receiver).")
            continue

        seq = parsed.get("seq")
        file_id = parsed.get("file_id")
        sender = parsed.get("sender")
        rec = parsed.get("receiver")
        print(f"Received data packet: seq={seq}, file_id={file_id}, burst_to={parsed.get('burst_to')}, sender={sender}, receiver={rec}")
        local_cs = args.my_callsign.strip().upper()
        if rec.strip().upper() != local_cs:
            print(f"Packet intended for {rec.strip().upper()}, not me ({local_cs}). Ignoring.")
            continue

        if file_id not in transfers:
            if seq != 1:
                print(f"Received non-header packet (seq={seq}) for unknown transfer {file_id}. Ignoring.")
                continue
            header_payload = parsed.get("payload")
            try:
                header_info = header_payload.decode('utf-8', errors='replace')
                parts = header_info.split("|")
                if len(parts) < 7:
                    print("Invalid header info – ignoring transfer.")
                    continue
                filename, orig_size, comp_size, md5_hash, file_id, comp_flag, total_str = parts[:7]
                orig_size = int(orig_size)
                comp_size = int(comp_size)
                compress = (comp_flag == "1")
                total_packets = int(total_str)
            except Exception as e:
                print("Error parsing header payload:", e)
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
                "ack_timer": None,
                "total": total_packets,
                "start_time": time.time(),
                "bytes_received": 0,
                "duplicate_count": 0,
                "burst_bytes": 0,
                "last_burst_ack_time": time.time()
            }
            print(f"Started transfer from {sender} (File: {filename}, ID: {file_id})")
            print(f"Total packets required (including header): {total_packets}")
            send_ack(args.my_callsign, sender, file_id, "0001")
            continue

        transfer = transfers[file_id]
        transfer["last_received"] = time.time()

        if seq in transfer["packets"]:
            transfer["duplicate_count"] = transfer.get("duplicate_count", 0) + 1
            print(f"Duplicate packet seq {seq} received; duplicates so far: {transfer['duplicate_count']}.")
            continue
        transfer["packets"][seq] = parsed.get("payload")
        # Update bytes received and burst bytes.
        packet_length = len(parsed.get("payload"))
        transfer["bytes_received"] += packet_length
        transfer["burst_bytes"] = transfer.get("burst_bytes", 0) + packet_length

        # *** NEW: Update the burst boundary for this transfer (cancel any pending ACK timer first) ***
        if seq >= 2:
            if transfer.get("ack_timer") is not None:
                transfer["ack_timer"].cancel()
                transfer["ack_timer"] = None
            transfer["burst_to"] = parsed.get("burst_to")

        ack_range = compute_cumulative_ack(transfer)
        print(f"Cumulative ACK computed: {ack_range}")
        if transfer.get("burst_to") is not None and seq == transfer.get("burst_to"):
            now = time.time()
            burst_duration = now - transfer["last_burst_ack_time"]
            burst_rate = transfer["burst_bytes"] / burst_duration if burst_duration > 0 else 0
            overall_elapsed = now - transfer["start_time"]
            overall_rate = transfer["bytes_received"] / overall_elapsed if overall_elapsed > 0 else 0
            progress = (transfer["bytes_received"] / transfer["comp_size"]) * 100
            eta = (transfer["comp_size"] - transfer["bytes_received"]) / overall_rate if overall_rate > 0 else float('inf')
            print(f"--- Stats ---")
            print(f"Previous burst: {transfer['burst_bytes']} bytes in {burst_duration:.2f}s ({burst_rate:.2f} bytes/s)")
            print(f"Overall: {transfer['bytes_received']}/{transfer['comp_size']} bytes ({progress:.2f}%), elapsed: {overall_elapsed:.2f}s, ETA: {eta:.2f}s")
            print(f"Overall bytes/sec: {overall_rate:.2f} bytes/s, Duplicates: {transfer['duplicate_count']}")
            print(f"--------------")
            send_ack(args.my_callsign, sender, file_id, ack_range)
            transfer["last_ack_sent"] = time.time()
            transfer["burst_bytes"] = 0
            transfer["last_burst_ack_time"] = now
        else:
            schedule_ack(transfer, sender, file_id)
        if transfer.get("total") is not None and len(transfer["packets"]) == transfer["total"] - 1:
            overall_elapsed = time.time() - transfer["start_time"]
            overall_rate = transfer["bytes_received"] / overall_elapsed if overall_elapsed > 0 else 0
            print(f"=== Receiver Final Summary for file {file_id} ===")
            print(f"Total bytes received: {transfer['bytes_received']} bytes in {overall_elapsed:.2f}s ({overall_rate:.2f} bytes/s), Duplicates: {transfer.get('duplicate_count', 0)}.")
            print("===============================================")
            print(f"Transfer complete for file {file_id}. Reassembling file …")
            data_parts = []
            complete = True
            for seq_num in range(2, transfer["total"] + 1):
                if seq_num not in transfer["packets"]:
                    print(f"Missing packet {seq_num} – cannot reassemble.")
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
                        print("Decompression error:", e)
                        continue
                except Exception as e:
                    print("Decompression error:", e)
                    continue
            computed_md5 = hashlib.md5(full_data).hexdigest()
            if computed_md5 == transfer["md5"]:
                print("Checksum OK.")
            else:
                print(f"Checksum mismatch! (Expected: {transfer['md5']}, Got: {computed_md5})")
            outname = transfer["filename"]
            base, ext = os.path.splitext(outname)
            cnt = 1
            while os.path.exists(outname):
                outname = f"{base}_{cnt}{ext}"
                cnt += 1
            with open(outname, 'wb') as f:
                f.write(full_data)
            print(f"Saved received file as {outname}")
            del transfers[file_id]
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
    args = parser.parse_args()
    DEBUG = args.debug
    if args.role == 'sender':
        if not args.receiver_callsign:
            print("Error: --receiver-callsign is required in sender mode.")
            sys.exit(1)
        if args.connection == 'serial' and not args.serial_port:
            print("Error: --serial-port is required for serial connection.")
            sys.exit(1)
        if args.connection == 'tcp' and not args.host:
            print("Error: --host is required for TCP connection.")
            sys.exit(1)
        if not args.file:
            print("Error: --file is required in sender mode.")
            sys.exit(1)
        sender_main(args)
    else:
        if args.connection == 'serial' and not args.serial_port:
            print("Error: --serial-port is required for serial connection.")
            sys.exit(1)
        receiver_main(args)

if __name__ == '__main__':
    main()
