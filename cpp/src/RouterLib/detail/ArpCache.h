#ifndef ROUTERLIB_DETAIL_ARPCACHE_H
#define ROUTERLIB_DETAIL_ARPCACHE_H

#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <optional>

#include "IRoutingTable.h"
#include "IPacketSender.h"

namespace RouterLib::detail {

struct ArpEntry {
    mac_addr mac;
    std::chrono::steady_clock::time_point added;
};

struct PacketQueueItem {
    Packet packet;
    std::string inIface;   // interface on which the packet was received (for ICMP errors)
    std::string outIface;  // interface on which packet will be sent out
};

struct ArpRequest {
    ip_addr ip; // IP address (network order) waiting for resolution
    std::vector<PacketQueueItem> waitingPackets;
    std::chrono::steady_clock::time_point lastSent;
    int attempts;
};

class ArpCache {
public:
    ArpCache(std::chrono::milliseconds timeout, std::chrono::milliseconds tickInterval,
             std::chrono::milliseconds resendInterval,
             std::shared_ptr<IPacketSender> sender,
             std::shared_ptr<IRoutingTable> routingTable);
    ~ArpCache() = default;

    // Check if MAC is in cache for given IP
    std::optional<mac_addr> lookup(ip_addr ip);
    // Queue a packet for the given IP (if not already resolved). Sends ARP request if needed.
    void queueRequest(ip_addr ip, Packet packet, const std::string& outIface, const std::string& inIface);
    // Handle an incoming ARP request packet
    void handleArpRequest(const Packet& packet, const std::string& inIface);
    // Handle an incoming ARP reply packet
    void handleArpReply(const Packet& packet);
    // Periodic tick to resend ARP requests and timeout cache entries
    void tick();

private:
    void sendArpRequest(ip_addr ip, const std::string& outIface);
    void insertMapping(ip_addr ip, const mac_addr& mac);

    std::unordered_map<ip_addr, ArpEntry> cache;    // ARP cache: IP -> (MAC, timestamp)
    std::vector<ArpRequest> requests;               // pending ARP requests

    std::chrono::milliseconds timeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;
    std::chrono::steady_clock::time_point lastTick;

    std::shared_ptr<IPacketSender> sender;
    std::shared_ptr<IRoutingTable> rt;
};

} // namespace RouterLib::detail

#endif // ROUTERLIB_DETAIL_ARPCACHE_H
