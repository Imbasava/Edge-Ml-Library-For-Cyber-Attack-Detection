#include <pcap.h>
#include <iostream>
#include <chrono>
#include <unordered_map>
#include <cmath>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "json.hpp"  // Make sure you have nlohmann/json.hpp

using json = nlohmann::json;


struct Stats {
    uint64_t packets = 0, bytes = 0, tcp = 0, udp = 0, icmp = 0, syn = 0, ack = 0;
    std::unordered_map<uint32_t, bool> ips;
    std::unordered_map<uint16_t, bool> ports;
    std::chrono::steady_clock::time_point start;
    
    void reset() {
        packets = bytes = tcp = udp = icmp = syn = ack = 0;
        ips.clear(); ports.clear();
        start = std::chrono::steady_clock::now();
    }
    
    void add_packet(uint32_t size, uint32_t src_ip, uint32_t dst_ip, 
                   uint16_t src_port, uint16_t dst_port, uint8_t proto,
                   bool is_syn, bool is_ack) {
        packets++; bytes += size;
        ips[src_ip] = ips[dst_ip] = true;
        if(src_port) ports[src_port] = true;
        if(dst_port) ports[dst_port] = true;
        
        if(proto == 6) { tcp++;
            if(is_syn) syn++; if(is_ack) ack++;
        } else if(proto == 17) udp++;
        else if(proto == 1) icmp++;
        
    }
};

Stats stats;
int window_size = 10;

void output_features() {
    double duration = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - stats.start).count();
    if(duration <= 0 || stats.packets == 0) return;
    
    // Calculate features
    double avg_size = (double)stats.bytes / stats.packets;
    double pps = stats.packets / duration;
    double bps = stats.bytes / duration;
    int unique_ips = stats.ips.size();
    int unique_ports = stats.ports.size();
    
    double total_proto = stats.tcp + stats.udp + stats.icmp;
    double tcp_ratio = total_proto > 0 ? stats.tcp / total_proto : 0;
    double udp_ratio = total_proto > 0 ? stats.udp / total_proto : 0;
    double syn_ratio = stats.tcp > 0 ? (double)stats.syn / stats.tcp : 0;
    double ack_ratio = stats.tcp > 0 ? (double)stats.ack / stats.tcp : 0;
    
    // MODIFIED: Using nlohmann::json for output
    json output;
    output["feature_type"] = "ddos";
    output["features"] = {
        {"Packet_Size", avg_size},
        {"Packets_Per_Sec", pps},
        {"Flow_Duration", duration},
        {"Bytes_Per_Sec", bps},
        {"Unique_IPs", unique_ips},
        {"Port_Diversity", unique_ports},
        {"TCP_Ratio", tcp_ratio},
        {"UDP_Ratio", udp_ratio},
        {"SYN_Flag_Ratio", syn_ratio},
        {"ACK_Flag_Ratio", ack_ratio}
    };
    
    std::cout << output.dump() << std::endl;
    
    stats.reset();
}

void packet_handler(u_char*, const struct pcap_pkthdr* header, const u_char* packet) {
    // Ethernet header
    struct ethhdr* eth = (struct ethhdr*)packet;
    if(ntohs(eth->h_proto) != ETH_P_IP) return;  // Check for IP packets
    
    // IP header (skip Ethernet header = 14 bytes)
    struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if(ip->version != 4) return;  // Only IPv4
    
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;
    uint8_t proto = ip->protocol;
    uint16_t src_port = 0, dst_port = 0;
    bool is_syn = false, is_ack = false;
    
    // Transport layer (skip IP header)
    int ip_header_len = ip->ihl * 4;
    const u_char* transport = packet + sizeof(struct ethhdr) + ip_header_len;
    
    if(proto == 6) { // TCP
        struct tcphdr* tcp = (struct tcphdr*)transport;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
        is_syn = tcp->syn;
        is_ack = tcp->ack;
    } else if(proto == 17) { // UDP
        struct udphdr* udp = (struct udphdr*)transport;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }
    
    stats.add_packet(header->len, src_ip, dst_ip, src_port, dst_port, proto, is_syn, is_ack);
    
    // Check if window completed
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - stats.start).count();
    if(elapsed >= window_size && stats.packets > 0) {
        output_features();
    }
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        std::cout << "Usage: " << argv[0] << " <interface> [window_size=10]" << std::endl;
        std::cout << "Example: " << argv[0] << " wlp0s20f3 10" << std::endl;
        return 1;
    }
    
    char* interface = argv[1];
    if(argc > 2) window_size = atoi(argv[2]);
    
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err);
    if(!handle) {
        std::cerr << "Error opening interface: " << err << std::endl;
        return 1;
    }
    
    // Set filter for IP packets only
    struct bpf_program fp;
    if(pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter" << std::endl;
        pcap_close(handle);
        return 1;
    }
    
    if(pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);
    
    stats.reset();
    std::cerr << "Capturing on " << interface << " (window: " << window_size << "s)" << std::endl;
    std::cerr << "Outputting features to stdout..." << std::endl;
    
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
    return 0;
}
