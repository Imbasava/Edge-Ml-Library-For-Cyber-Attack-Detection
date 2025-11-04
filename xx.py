import os
import sys
import time
import json
import threading
import subprocess

# --- Configuration ---
INTERFACE = 'wlan0' # IMPORTANT: Change this to your network interface (e.g., 'eth0', 'enp0s3')
FLOW_TIMEOUT_SECONDS = 15 # How long before an inactive flow is considered expired
REAPER_INTERVAL_SECONDS = 5 # How often the reaper thread runs to check for expired/active flows

# --- Configuration for Active Flow Sampling ---
ACTIVE_FLOW_MIN_DURATION = 5 # A flow must be active for at least this long to be sampled periodically
ACTIVE_FLOW_SAMPLE_INTERVAL = 3 # How often to sample features from an active flow

# --- Flow Class ---
class Flow:
    def __init__(self, first_packet):
        self.proto = first_packet['proto']

        # --- NEW: Set originator and responder based on the first packet ---
        self.orig_ip = first_packet['src_ip']
        self.orig_port = first_packet['src_port']
        self.resp_ip = first_packet['dst_ip']
        self.resp_port = first_packet['dst_port']

        self.start_time = first_packet['timestamp']
        self.last_seen = self.start_time
        self.last_sampled_time = self.start_time

        # --- NEW: Separate counters for originator and responder ---
        self.orig_pkts = 0
        self.orig_bytes = 0
        self.resp_pkts = 0
        self.resp_bytes = 0

        self.history = ''
        self.is_established = False
        self.fin_seen = False

        self.add_packet(first_packet)

    def add_packet(self, packet):
        self.last_seen = packet['timestamp']

        # --- NEW: Check packet direction and update appropriate counters ---
        if packet['src_ip'] == self.orig_ip and packet['src_port'] == self.orig_port:
            # Packet is from the originator
            self.orig_pkts += 1
            self.orig_bytes += packet['length']
        else:
            # Packet is from the responder
            self.resp_pkts += 1
            self.resp_bytes += packet['length']

        # Update TCP flags history (this logic remains the same)
        if self.proto == 'tcp' and packet['flags']:
            flags = packet['flags']
            if 'S' in flags and '.' not in flags: self.history += 's'
            elif 'S' in flags and '.' in flags: self.history += 'h'
            elif '.' in flags and 's' in self.history and not self.is_established:
                self.history += 'a'
                self.is_established = True
            elif 'F' in flags: self.history += 'f'; self.fin_seen = True
            elif 'R' in flags: self.history += 'r'
            elif 'P' in flags and self.is_established:
                if not self.history.endswith('d'): self.history += 'd'

    def get_conn_state(self):
        # This logic remains the same
        if self.is_established: return 'SF'
        if 's' in self.history and not self.is_established and 'r' not in self.history: return 'S0'
        if 'r' in self.history: return 'REJ'
        if 's' in self.history and 'h' not in self.history and not self.is_established: return 'S1'
        return 'OTH'

    def to_feature_dict(self):
        # --- REWRITTEN: Output exactly the features your model needs ---
        duration = self.last_seen - self.start_time
        service_map = {'80':'http', '443':'ssl', '22':'ssh', '21':'ftp', '53':'dns'}
        service = service_map.get(str(self.resp_port), 'unknown')
        if service == 'unknown':
            service = service_map.get(str(self.orig_port), 'unknown')

        return {
            "proto": self.proto,
            "service": service,
            "duration": round(duration, 6),
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "conn_state": self.get_conn_state(),
            "history": self.history.upper() if self.history else "NONE",
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts
        }

# --- Main Application Class (LiveFeatureProducer) ---
# This class and its methods (parse_tcpdump_line, expire_flows_periodically, start, etc.)
# do not need to be changed. The core logic modification was in the Flow class.
class LiveFeatureProducer:
    def __init__(self):
        self.active_flows = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def get_flow_key(self, p):
        # Normalize the key so that originator->responder and responder->originator packets
        # map to the same Flow object.
        addr1 = (p['src_ip'], p['src_port'])
        addr2 = (p['dst_ip'], p['dst_port'])
        return (p['proto'], *sorted((addr1, addr2)))

    def parse_tcpdump_line(self, line):
        parts = line.split()
        if len(parts) < 5 or parts[1] != 'IP': return None
        try:
            timestamp = time.time()
            src_full, dst_full = parts[2], parts[4].strip(':')
            src_ip, src_port_str = src_full.rsplit('.', 1)
            dst_ip, dst_port_str = dst_full.rsplit('.', 1)
            src_port, dst_port = int(src_port_str), int(dst_port_str)
            proto, flags, length = 'unknown', '', 0
            if 'UDP,' in line: proto = 'udp'
            elif 'ICMP' in line: proto, src_port, dst_port = 'icmp', 0, 0
            elif 'Flags [' in line:
                proto = 'tcp'
                flags_start = line.find('Flags [') + 7
                flags = line[flags_start:line.find(']', flags_start)]
            if 'length ' in line:
                length_str = line.split('length ')[-1].strip()
                if length_str.isdigit(): length = int(length_str)
            if proto == 'unknown': return None
            return {
                'timestamp': timestamp, 'src_ip': src_ip, 'src_port': src_port,
                'dst_ip': dst_ip, 'dst_port': dst_port, 'proto': proto,
                'flags': flags, 'length': length
            }
        except (ValueError, IndexError): return None

    def process_line(self, line):
        packet = self.parse_tcpdump_line(line)
        if not packet: return
        flow_key = self.get_flow_key(packet)
        with self.lock:
            if flow_key in self.active_flows:
                self.active_flows[flow_key].add_packet(packet)
            else:
                self.active_flows[flow_key] = Flow(packet)

    def expire_flows_periodically(self):
        while not self.stop_event.is_set():
            time.sleep(REAPER_INTERVAL_SECONDS)
            now = time.time()
            expired_keys = []
            features_for_model = []
            with self.lock:
                for key, flow in list(self.active_flows.items()):
                    if (now - flow.last_seen) > FLOW_TIMEOUT_SECONDS or flow.fin_seen:
                        expired_keys.append(key)
                        features_for_model.append(flow.to_feature_dict())
                    else:
                        if (now - flow.start_time) >= ACTIVE_FLOW_MIN_DURATION and \
                           (now - flow.last_sampled_time) >= ACTIVE_FLOW_SAMPLE_INTERVAL:
                            features_for_model.append(flow.to_feature_dict())
                            flow.last_sampled_time = now
                for key in expired_keys:
                    self.active_flows.pop(key)
            for features in features_for_model:
                print(json.dumps(features))
                sys.stdout.flush()

    def start(self):
        reaper_thread = threading.Thread(target=self.expire_flows_periodically, daemon=True)
        reaper_thread.start()
        command = ['tcpdump', '-i', INTERFACE, '-n', '-l', 'ip or ip6 or icmp']
        print(f"[*] Feature Producer started on {INTERFACE}. Piping JSON to stdout...", file=sys.stderr)
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in iter(proc.stdout.readline, ''):
                self.process_line(line.strip())
        except KeyboardInterrupt:
            print("\n[!] Shutdown signal received.", file=sys.stderr)
        finally:
            self.stop_event.set()
            if 'proc' in locals(): proc.terminate()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script needs root privileges for tcpdump.", file=sys.stderr)
        sys.exit(1)
    producer = LiveFeatureProducer()
    producer.start()