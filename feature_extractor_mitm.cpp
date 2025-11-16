// Filename: arp_monitor.cpp
// Purpose: Extract ALL 8 features required by the MITM detection model.
// Features: mac_ip_inconsistency, packet_in_count, packet_rate, rtt_avg,
//           is_broadcast, arp_request, arp_reply, op_code_arp

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <cstring>
#include <csignal>
#include <thread>
#include <mutex>
#include <iomanip>
#include <unistd.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "json.hpp"  // Make sure you have nlohmann/json.hpp

using json = nlohmann::json;

// --- Configuration ---
// !!! IMPORTANT: CHANGE THIS TO YOUR NETWORK INTERFACE NAME !!!
const std::string INTERFACE = "wlp0s20f3"; // Example: "eth0", "en0", "wlan0"
const int SAMPLE_WINDOW_SECONDS = 10;  // Time window for aggregation
const int REAPER_INTERVAL_SECONDS = 5;

// --- ARP Packet Structure ---
struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed));

// --- Per-IP Statistics ---
struct IPStats {
    std::string ip_address;
    std::map<std::string, int> mac_bindings;
    std::string dominant_mac;
    int total_packets = 0;
    int mac_mismatches = 0;
    int arp_request_count = 0;
    int arp_reply_count = 0;
    int broadcast_count = 0;
    std::map<std::string, std::chrono::steady_clock::time_point> pending_requests;
    std::vector<double> rtt_samples;
    std::chrono::steady_clock::time_point window_start;
    std::chrono::steady_clock::time_point last_seen;
    
    IPStats() {
        window_start = std::chrono::steady_clock::now();
        last_seen = window_start;
    }
    
    // Convert stats to a JSON-like string for the Python script
    void print_features_json() const {
        auto now = std::chrono::steady_clock::now();
        double duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - window_start).count() / 1000.0;
        
        double mac_ip_inconsistency = (total_packets > 0) ? static_cast<double>(mac_mismatches) / total_packets : 0.0;
        int packet_in_count = total_packets;
        double packet_rate = (duration > 0) ? (total_packets / duration) : 0.0;
        
        double rtt_avg = 0.0;
        if (!rtt_samples.empty()) {
            double sum = 0.0;
            for (double rtt : rtt_samples) sum += rtt;
            rtt_avg = sum / rtt_samples.size();
        }
        
        int is_broadcast = (broadcast_count > 0) ? 1 : 0;
        int arp_request = arp_request_count;
        int arp_reply = arp_reply_count;
        int op_code_arp = (arp_request_count >= arp_reply_count) ? 1 : 2;
        
        // MODIFIED: Using nlohmann::json instead of manual JSON construction
        json output;
        output["feature_type"] = "mitm";
        output["ip_address"] = ip_address;
        output["features"] = {mac_ip_inconsistency, packet_in_count, packet_rate, rtt_avg,
                             is_broadcast, arp_request, arp_reply, op_code_arp};
        
        std::cout << output.dump() << std::endl;
    }
    
    void update_mac_binding(const std::string& mac) {
        mac_bindings[mac]++;
        std::string max_mac;
        int max_count = 0;
        for (const auto& pair : mac_bindings) {
            if (pair.second > max_count) {
                max_count = pair.second;
                max_mac = pair.first;
            }
        }
        if (!dominant_mac.empty() && mac != dominant_mac) {
            mac_mismatches++;
        }
        dominant_mac = max_mac;
    }
};

// --- Global State ---
std::map<std::string, IPStats> ip_statistics;
std::mutex stats_mutex;
bool stop_capture = false;
pcap_t* handle = nullptr;

// --- Helper Functions ---
std::string mac_to_string(const uint8_t* mac) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

std::string ip_to_string(const uint8_t* ip) {
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return std::string(buffer);
}

bool is_broadcast_mac(const uint8_t* mac) {
    return (mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff);
}

// --- Packet Processing ---
void process_arp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    auto now = std::chrono::steady_clock::now();
    if (ntohs(((struct ether_header*)packet)->ether_type) != ETHERTYPE_ARP) return;

    struct arp_header* arp = (struct arp_header*)(packet + sizeof(struct ether_header));
    uint16_t opcode = ntohs(arp->opcode);
    std::string sender_ip = ip_to_string(arp->sender_ip);
    
    std::lock_guard<std::mutex> guard(stats_mutex);
    if (ip_statistics.find(sender_ip) == ip_statistics.end()) {
        ip_statistics[sender_ip].ip_address = sender_ip;
    }
    
    IPStats& stats = ip_statistics[sender_ip];
    stats.last_seen = now;
    stats.total_packets++;
    stats.update_mac_binding(mac_to_string(arp->sender_mac));

    if (opcode == 1) { // ARP Request
        stats.arp_request_count++;
        stats.pending_requests[ip_to_string(arp->target_ip)] = now;
    } else if (opcode == 2) { // ARP Reply
        stats.arp_reply_count++;
        std::string target_ip_str = ip_to_string(arp->target_ip);
        if (ip_statistics.count(target_ip_str)) {
            auto& requester_stats = ip_statistics[target_ip_str];
            auto it = requester_stats.pending_requests.find(sender_ip);
            if (it != requester_stats.pending_requests.end()) {
                double rtt_ms = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second).count() / 1000.0;
                requester_stats.rtt_samples.push_back(rtt_ms);
                requester_stats.pending_requests.erase(it);
            }
        }
    }
    if (is_broadcast_mac(((struct ether_header*)packet)->ether_dhost)) {
        stats.broadcast_count++;
    }
}

// --- Periodic Sampling and Expiration ---
void sample_and_expire() {
    while (!stop_capture) {
        std::this_thread::sleep_for(std::chrono::seconds(REAPER_INTERVAL_SECONDS));
        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> ips_to_remove;
        
        stats_mutex.lock();
        for (auto& pair : ip_statistics) {
            IPStats& stats = pair.second;
            double window_duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.window_start).count();
            double time_since_last_seen = std::chrono::duration_cast<std::chrono::seconds>(now - stats.last_seen).count();
            
            if (window_duration >= SAMPLE_WINDOW_SECONDS || time_since_last_seen > SAMPLE_WINDOW_SECONDS) {
                if (stats.total_packets > 0) {
                    stats.print_features_json();
                }
                if (time_since_last_seen > SAMPLE_WINDOW_SECONDS) {
                    ips_to_remove.push_back(pair.first);
                } else {
                    stats = IPStats(); // Reset for next window
                    stats.ip_address = pair.first;
                }
            }
        }
        for (const auto& ip : ips_to_remove) ip_statistics.erase(ip);
        stats_mutex.unlock();
    }
}

// --- Signal Handling ---
void signal_handler(int signum) {
    std::cerr << "\n[!] Shutdown signal received." << std::endl;
    stop_capture = true;
    if (handle) pcap_breakloop(handle);
}

// --- Main ---
int main() {
    if (geteuid() != 0) {
        std::cerr << "[-] This program requires root privileges." << std::endl;
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(INTERFACE.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "[-] Couldn't open device " << INTERFACE << ": " << errbuf << std::endl;
        return 2;
    }
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[-] Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        return 4;
    }
    
    std::thread sampler_thread(sample_and_expire);
    std::cerr << "[*] ARP Monitor started on " << INTERFACE << ". Piping JSON to stdout..." << std::endl;
    
    pcap_loop(handle, -1, process_arp_packet, nullptr);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    sampler_thread.join();
    
    std::cerr << "[+] ARP Monitor shut down." << std::endl;
    return 0;
}