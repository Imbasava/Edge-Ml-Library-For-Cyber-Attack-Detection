""" # Filename: live_feature_producer.py
# Purpose: Captures live traffic, creates flows, and prints them as JSON to stdout.
#          This script acts as the data source for our security library.

import os
import sys
import time
import json
import threading
import subprocess

# --- Configuration ---
INTERFACE = 'wlan0' # IMPORTANT: Change this to your network interface (e.g., 'eth0')
FLOW_TIMEOUT_SECONDS = 15
REAPER_INTERVAL_SECONDS = 5

# --- Flow Class (Copied from your tested version) ---
class Flow:
    def __init__(self, first_packet):
        self.proto = first_packet['proto']
        # Normalize flow direction
        if (first_packet['src_ip'], first_packet['src_port']) > (first_packet['dst_ip'], first_packet['dst_port']):
            self.src_ip, self.src_port = first_packet['dst_ip'], first_packet['dst_port']
            self.dst_ip, self.dst_port = first_packet['src_ip'], first_packet['src_port']
        else:
            self.src_ip, self.src_port = first_packet['src_ip'], first_packet['src_port']
            self.dst_ip, self.dst_port = first_packet['dst_ip'], first_packet['dst_port']

        self.start_time = first_packet['timestamp']
        self.last_seen = self.start_time
        self.orig_pkts = 0
        self.orig_bytes = 0
        self.history = ''
        self.is_established = False
        self.fin_seen = False
        self.add_packet(first_packet)

    def add_packet(self, packet):
        self.last_seen = packet['timestamp']
        self.orig_pkts += 1
        self.orig_bytes += packet['length']
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
        if self.is_established: return 'SF'
        if 's' in self.history and not self.is_established and 'r' not in self.history: return 'S0'
        if 'r' in self.history: return 'REJ'
        if 's' in self.history and 'h' not in self.history and not self.is_established: return 'S1'
        return 'OTH'

    def to_feature_dict(self):
        duration = self.last_seen - self.start_time
        service_map = {'80':'http', '443':'ssl', '22':'ssh', '21':'ftp', '53':'dns'}
        service = service_map.get(str(self.dst_port), 'unknown')
        if service == 'unknown':
            service = service_map.get(str(self.src_port), 'unknown')

        return {
            "proto": self.proto, "service": service, "conn_state": self.get_conn_state(),
            "history": self.history.upper() if self.history else "NONE",
            "duration": round(duration, 6), "orig_bytes": self.orig_bytes,
            "orig_pkts": self.orig_pkts, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port
        }

# --- Main Application Class (Copied from your tested version) ---
class LiveFeatureProducer:
    def __init__(self):
        self.active_flows = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def get_flow_key(self, p):
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
            with self.lock:
                for key, flow in self.active_flows.items():
                    if (now - flow.last_seen) > FLOW_TIMEOUT_SECONDS or flow.fin_seen:
                        expired_keys.append(key)
                for key in expired_keys:
                    final_flow = self.active_flows.pop(key)
                    features = final_flow.to_feature_dict()
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
    producer.start() """









// Filename: producer.cpp
// Purpose: A high-performance C++ version of the live_feature_producer.py script.
// It captures live traffic using libpcap, creates flows, and prints them as JSON to stdout.

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <csignal>
#include <iomanip>

// Networking headers
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

// For checking root privileges
#include <unistd.h>

// Include the single-header JSON library we downloaded
#include "json.hpp"

// Use nlohmann::json for convenience
using json = nlohmann::json;

// --- Configuration ---
const std::string INTERFACE = "wlan0"; // IMPORTANT: Change to your interface
const int FLOW_TIMEOUT_SECONDS = 15;
const int REAPER_INTERVAL_SECONDS = 5;

// --- Flow Key and Flow Data Structures ---

// A struct to represent the unique key for a flow.
// We need to define the '<' operator so we can use it as a key in std::map.
struct FlowKey {
    std::string proto;
    std::string ip1, ip2;
    int port1, port2;

    bool operator<(const FlowKey& other) const {
        if (proto != other.proto) return proto < other.proto;
        if (ip1 != other.ip1) return ip1 < other.ip1;
        if (port1 != other.port1) return port1 < other.port1;
        if (ip2 != other.ip2) return ip2 < other.ip2;
        return port2 < other.port2;
    }
};

// A struct to hold all the data for an active flow.
// This is the C++ equivalent of your Python 'Flow' class.
struct Flow {
    std::string proto;
    std::string src_ip, dst_ip;
    int src_port, dst_port;
    
    std::chrono::time_point<std::chrono::steady_clock> start_time;
    std::chrono::time_point<std::chrono::steady_clock> last_seen;
    
    long orig_pkts = 0;
    long orig_bytes = 0;
    std::string history = "";
    bool is_established = false;
    bool fin_seen = false;

    // Helper function to derive the connection state, just like in Python
    std::string get_conn_state() const {
        if (is_established) return "SF";
        if (history.find('s') != std::string::npos && !is_established && history.find('r') == std::string::npos) return "S0";
        if (history.find('r') != std::string::npos) return "REJ";
        if (history.find('s') != std::string::npos && history.find('h') == std::string::npos && !is_established) return "S1";
        return "OTH";
    }

    // Convert the flow data to a JSON object
    json to_json() const {
        double duration = std::chrono::duration_cast<std::chrono::microseconds>(last_seen - start_time).count() / 1000000.0;
        
        // Simple service mapping
        std::map<int, std::string> service_map = {{80, "http"}, {443, "ssl"}, {22, "ssh"}, {21, "ftp"}, {53, "dns"}};
        std::string service = "unknown";
        if (service_map.count(dst_port)) {
            service = service_map[dst_port];
        } else if (service_map.count(src_port)) {
            service = service_map[src_port];
        }

        // Convert history to uppercase
        std::string history_upper = history;
        for(char &c : history_upper) c = toupper(c);

        return json{
            {"proto", proto},
            {"service", service},
            {"conn_state", get_conn_state()},
            {"history", history.empty() ? "NONE" : history_upper},
            {"duration", duration},
            {"orig_bytes", orig_bytes},
            {"orig_pkts", orig_pkts},
            {"src_ip", src_ip},
            {"dst_ip", dst_ip},
            {"src_port", src_port},
            {"dst_port", dst_port}
        };
    }
};

// --- Global State ---
// This map holds all the flows we are currently tracking.
std::map<FlowKey, Flow> active_flows;
// A mutex is needed to prevent race conditions when the main thread and the
// reaper thread access the active_flows map at the same time.
std::mutex flow_mutex;
bool stop_capture = false;

// --- Flow Expiration Logic ---
// This function runs in a separate thread to clean up old flows.
// It's the C++ equivalent of your 'expire_flows_periodically'.
void expire_flows() {
    while (!stop_capture) {
        std::this_thread::sleep_for(std::chrono::seconds(REAPER_INTERVAL_SECONDS));
        
        auto now = std::chrono::steady_clock::now();
        std::vector<FlowKey> expired_keys;

        // Lock the mutex to safely access the active_flows map
        flow_mutex.lock();
        for (const auto& pair : active_flows) {
            double time_since_last_seen = std::chrono::duration_cast<std::chrono::seconds>(now - pair.second.last_seen).count();
            if (time_since_last_seen > FLOW_TIMEOUT_SECONDS || pair.second.fin_seen) {
                expired_keys.push_back(pair.first);
            }
        }

        for (const auto& key : expired_keys) {
            // Print the finished flow as a JSON line to standard output
            std::cout << active_flows[key].to_json().dump() << std::endl;
            active_flows.erase(key);
        }
        // Unlock the mutex
        flow_mutex.unlock();
    }
}

// --- Packet Processing Callback ---
// This is the core function. libpcap will call this for every packet it captures.
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    auto now = std::chrono::steady_clock::now();

    // This is the most complex part: parsing the raw packet bytes.
    // We cast the raw byte buffer to different C structs representing the protocol headers.
    const struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return; // Not an IP packet

    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    const struct tcphdr* tcp_header = nullptr;
    const struct udphdr* udp_header = nullptr;

    int ip_header_len = ip_header->ip_hl * 4;
    int src_port = 0, dst_port = 0;
    std::string proto_str;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        // ntohs converts from "Network Byte Order" to "Host Byte Order"
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        proto_str = "tcp";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        proto_str = "udp";
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        proto_str = "icmp";
    } else {
        return; // Not a protocol we are tracking
    }
    
    // Get IP addresses
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    // Create a normalized flow key, just like in the Python version
    FlowKey key;
    key.proto = proto_str;
    if (std::string(src_ip_str) < std::string(dst_ip_str) || 
       (std::string(src_ip_str) == std::string(dst_ip_str) && src_port < dst_port)) {
        key.ip1 = src_ip_str; key.port1 = src_port;
        key.ip2 = dst_ip_str; key.port2 = dst_port;
    } else {
        key.ip1 = dst_ip_str; key.port1 = dst_port;
        key.ip2 = src_ip_str; key.port2 = src_port;
    }

    // Lock the mutex to safely modify the flow map
    std::lock_guard<std::mutex> guard(flow_mutex);

    if (active_flows.find(key) == active_flows.end()) {
        // This is a new flow
        Flow new_flow;
        new_flow.start_time = now;
        new_flow.src_ip = src_ip_str; new_flow.dst_ip = dst_ip_str;
        new_flow.src_port = src_port; new_flow.dst_port = dst_port;
        new_flow.proto = proto_str;
        active_flows[key] = new_flow;
    }

    // Update the existing flow
    Flow& flow = active_flows[key];
    flow.last_seen = now;
    flow.orig_pkts++;
    flow.orig_bytes += header->len;

    // Update TCP history, similar to the Python logic
    if (tcp_header) {
        if (tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK)) flow.history += 's';
        else if (tcp_header->th_flags & TH_SYN && tcp_header->th_flags & TH_ACK) flow.history += 'h';
        else if (tcp_header->th_flags & TH_ACK && flow.history.find('s') != std::string::npos && !flow.is_established) {
            flow.history += 'a';
            flow.is_established = true;
        }
        else if (tcp_header->th_flags & TH_FIN) { flow.history += 'f'; flow.fin_seen = true; }
        else if (tcp_header->th_flags & TH_RST) { flow.history += 'r'; }
        else if (tcp_header->th_flags & TH_PUSH && flow.is_established) {
            if (flow.history.empty() || flow.history.back() != 'd') flow.history += 'd';
        }
    }
}

// --- Main Execution ---
pcap_t* handle; // Global handle for cleanup

void signal_handler(int signum) {
    std::cerr << "\n[!] Shutdown signal received." << std::endl;
    stop_capture = true;
    if (handle) {
        pcap_breakloop(handle);
    }
}

int main() {
    if (geteuid() != 0) {
        std::cerr << "[-] This script needs root privileges for libpcap." << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler); // Handle Ctrl+C

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the network interface for live capture
    handle = pcap_open_live(INTERFACE.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "[-] Couldn't open device " << INTERFACE << ": " << errbuf << std::endl;
        return 2;
    }

    // Start the flow expiration thread
    std::thread reaper_thread(expire_flows);

    std::cerr << "[*] C++ Feature Producer started on " << INTERFACE << ". Piping JSON to stdout..." << std::endl;
    
    // Start the main capture loop. This will call 'process_packet' for each packet.
    // A value of -1 means it will loop forever until pcap_breakloop is called.
    pcap_loop(handle, -1, process_packet, nullptr);

    // Cleanup
    pcap_close(handle);
    reaper_thread.join(); // Wait for the reaper thread to finish
    std::cerr << "[+] Producer shut down." << std::endl;
    
    return 0;
}