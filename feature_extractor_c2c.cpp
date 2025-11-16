// Filename: producer_v2.cpp
// Purpose: A high-performance C++ producer that implements bidirectional flow tracking
//          and active flow sampling for long-lived connections.

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <csignal>
#include <iomanip>
#include <unistd.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "json.hpp"

using json = nlohmann::json;

// --- Configuration ---
const std::string INTERFACE = "wlp0s20f3";
const int FLOW_TIMEOUT_SECONDS = 15;
const int REAPER_INTERVAL_SECONDS = 5;

// --- NEW: Configuration for Active Flow Sampling ---
const int ACTIVE_FLOW_MIN_DURATION = 5;    // A flow must be active for this long to be sampled
const int ACTIVE_FLOW_SAMPLE_INTERVAL = 5; // How often to sample to be taken

// --- Flow Key and Flow Data Structures ---
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

struct Flow {
    std::string proto;
    // --- NEW: Explicit originator/responder fields ---
    std::string orig_ip, resp_ip;
    int orig_port, resp_port;
    
    std::chrono::time_point<std::chrono::steady_clock> start_time;
    std::chrono::time_point<std::chrono::steady_clock> last_seen;
    // --- NEW: Timestamp for the last active sample ---
    std::chrono::time_point<std::chrono::steady_clock> last_sampled_time;
    
    // --- NEW: Separate counters for originator and responder ---
    long orig_pkts = 0;
    long orig_bytes = 0;
    long resp_pkts = 0;
    long resp_bytes = 0;

    std::string history = "";
    bool is_established = false;
    bool fin_seen = false;

    std::string get_conn_state() const {
        if (is_established) return "SF";
        if (history.find('s') != std::string::npos && !is_established && history.find('r') == std::string::npos) return "S0";
        if (history.find('r') != std::string::npos) return "REJ";
        if (history.find('s') != std::string::npos && history.find('h') == std::string::npos && !is_established) return "S1";
        return "OTH";
    }

    // --- REWRITTEN: to_json now outputs the features required by the new model ---
    json to_json() const {
        double duration = std::chrono::duration_cast<std::chrono::microseconds>(last_seen - start_time).count() / 1000000.0;
        
        std::map<int, std::string> service_map = {{80, "http"}, {443, "ssl"}, {22, "ssh"}, {21, "ftp"}, {53, "dns"}};
        std::string service = "unknown";
        if (service_map.count(resp_port)) {
            service = service_map[resp_port];
        } else if (service_map.count(orig_port)) {
            service = service_map[orig_port];
        }

        std::string history_upper = history;
        for(char &c : history_upper) c = toupper(c);

        return json{
            {"proto", proto},
            {"service", service},
            {"duration", duration},
            {"orig_bytes", orig_bytes},
            {"resp_bytes", resp_bytes},
            {"conn_state", get_conn_state()},
            {"history", history.empty() ? "NONE" : history_upper},
            {"orig_pkts", orig_pkts},
            {"resp_pkts", resp_pkts}
        };
    }
};

// --- Global State ---
std::map<FlowKey, Flow> active_flows;
std::mutex flow_mutex;
bool stop_capture = false;

// --- Flow Expiration and Sampling Logic ---
// --- REWRITTEN: This function now handles both expiration AND active sampling ---
void expire_and_sample_flows() {
    while (!stop_capture) {
        std::this_thread::sleep_for(std::chrono::seconds(REAPER_INTERVAL_SECONDS));
        
        auto now = std::chrono::steady_clock::now();
        std::vector<FlowKey> expired_keys;
        std::vector<json> features_to_print;

        flow_mutex.lock();
        // We iterate by reference to be able to modify last_sampled_time
        for (auto& pair : active_flows) {
            Flow& flow = pair.second;
            double time_since_last_seen = std::chrono::duration_cast<std::chrono::seconds>(now - flow.last_seen).count();

            // Condition 1: Flow is expired or finished
            if (time_since_last_seen > FLOW_TIMEOUT_SECONDS || flow.fin_seen) {
                expired_keys.push_back(pair.first);
                json output = flow.to_json();
                output["feature_type"] = "c2c";  // ADDED: Feature type identifier
                features_to_print.push_back(output);
            } 
            // Condition 2: Flow is long-lived and ready for an active sample
            else {
                double flow_age = std::chrono::duration_cast<std::chrono::seconds>(now - flow.start_time).count();
                double time_since_last_sample = std::chrono::duration_cast<std::chrono::seconds>(now - flow.last_sampled_time).count();

                if (flow_age >= ACTIVE_FLOW_MIN_DURATION && time_since_last_sample >= ACTIVE_FLOW_SAMPLE_INTERVAL) {
                    json output = flow.to_json();
                    output["feature_type"] = "c2c";  // ADDED: Feature type identifier
                    features_to_print.push_back(output);
                    flow.last_sampled_time = now; // Update the sample time
                }
            }
        }

        // Remove expired flows from the map
        for (const auto& key : expired_keys) {
            active_flows.erase(key);
        }
        flow_mutex.unlock();

        // Print all collected features (from both expired and active flows)
        for (const auto& features : features_to_print) {
            std::cout << features.dump() << std::endl;
        }
    }
}


// --- Packet Processing Callback ---
// --- MODIFIED: To handle bidirectional counting ---
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    auto now = std::chrono::steady_clock::now();

    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    const struct tcphdr* tcp_header = nullptr;

    int ip_header_len = ip_header->ip_hl * 4;
    int src_port = 0, dst_port = 0;
    std::string proto_str;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        proto_str = "tcp";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // UDP logic...
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        proto_str = "udp";
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        proto_str = "icmp";
    } else {
        return;
    }
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

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

    std::lock_guard<std::mutex> guard(flow_mutex);

    if (active_flows.find(key) == active_flows.end()) {
        // This is a new flow. Set the originator/responder based on this first packet.
        Flow new_flow;
        new_flow.start_time = now;
        new_flow.last_sampled_time = now;
        new_flow.proto = proto_str;
        new_flow.orig_ip = src_ip_str;
        new_flow.orig_port = src_port;
        new_flow.resp_ip = dst_ip_str;
        new_flow.resp_port = dst_port;
        active_flows[key] = new_flow;
    }

    Flow& flow = active_flows[key];
    flow.last_seen = now;

    // --- NEW: Check packet direction and update the correct counters ---
    if (std::string(src_ip_str) == flow.orig_ip && src_port == flow.orig_port) {
        // Packet is from the originator
        flow.orig_pkts++;
        flow.orig_bytes += header->len;
    } else {
        // Packet is from the responder
        flow.resp_pkts++;
        flow.resp_bytes += header->len;
    }

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

// --- Main Execution and Signal Handling (No changes needed here) ---
pcap_t* handle;

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

    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(INTERFACE.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "[-] Couldn't open device " << INTERFACE << ": " << errbuf << std::endl;
        return 2;
    }

    // Start the new expiration and sampling thread
    std::thread reaper_thread(expire_and_sample_flows);

    std::cerr << "[*] C++ Feature Producer (v2) started on " << INTERFACE << ". Piping JSON to stdout..." << std::endl;
    
    pcap_loop(handle, -1, process_packet, nullptr);

    pcap_close(handle);
    reaper_thread.join();
    std::cerr << "[+] Producer shut down." << std::endl;
    
    return 0;
}