#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <chrono>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <vector>
#include <cstring>

#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"

// Extended ARP entry to store resolved MAC address, pending state, and a queue of waiting packets.
struct ArpEntry {
    std::chrono::steady_clock::time_point timeAdded;
    mac_addr mac;              // Resolved MAC address.
    bool valid = false;        // True if the ARP entry has been resolved.
    int requestCount = 0;      // Number of ARP requests sent.
    std::chrono::steady_clock::time_point lastRequestSent;
    // Queue of packets waiting for ARP resolution; each pair holds (packet, outgoing interface)
    std::vector<std::pair<Packet, std::string>> pendingPackets;
};

class ArpCache {
public:
    ArpCache(
        std::chrono::milliseconds entryTimeout,
        std::chrono::milliseconds tickInterval,
        std::chrono::milliseconds resendInterval,
        std::shared_ptr<IPacketSender> packetSender, 
        std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache();

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac);

    std::optional<mac_addr> getEntry(uint32_t ip);

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface);

private:
    void loop();

    std::chrono::milliseconds entryTimeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;

    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::mutex mutex;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
};

#endif //ARPCACHE_H
