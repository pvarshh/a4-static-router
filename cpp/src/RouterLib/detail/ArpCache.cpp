#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, 
    std::chrono::milliseconds tickInterval, 
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender, 
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable))
{
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();

    // Process pending ARP requests: if it's time to resend, do so (up to 7 attempts)
    for (auto& [ip, entry] : entries) {
        if (!entry.valid) {
            if (now - entry.lastRequestSent >= resendInterval) {
                if (entry.requestCount >= 7) {
                    // After 7 attempts, drop queued packets and log an error.
                    for (const auto &pkt_info : entry.pendingPackets) {
                        spdlog::error("ARP request for IP {} failed 7 times. Dropping queued packet.", ip);
                        // In a full implementation, you may also send an ICMP host unreachable.
                    }
                    entry.pendingPackets.clear();
                } else {
                    spdlog::info("Resending ARP request for IP: {}", ip);
                    // *** ARP REQUEST PACKET GENERATION NOT IMPLEMENTED ***
                    // Example:
                    // Packet arpReq = buildArpRequest(ip);
                    // packetSender->sendPacket(arpReq, /* appropriate interface */);
                    entry.lastRequestSent = now;
                    entry.requestCount++;
                }
            }
        }
    }

    // Remove entries that have timed out.
    std::erase_if(entries, [this, now](const auto& pair) {
        return now - pair.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    auto it = entries.find(ip);
    if (it != entries.end()) {
        // Update the pending entry into a valid entry.
        it->second.mac = mac;
        it->second.valid = true;
        it->second.timeAdded = now;
        // Immediately send any queued packets.
        for (const auto &pkt_info : it->second.pendingPackets) {
            Packet pkt = pkt_info.first;
            const std::string& iface = pkt_info.second;
            // *** Update packet's Ethernet header destination MAC to the resolved MAC ***
            // For example: setDestinationMac(pkt, mac);
            packetSender->sendPacket(pkt, iface);
        }
        it->second.pendingPackets.clear();
    } else {
        // Create a new valid entry.
        ArpEntry entry;
        entry.mac = mac;
        entry.valid = true;
        entry.timeAdded = now;
        entry.requestCount = 0;
        entries[ip] = entry;
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);
    auto it = entries.find(ip);
    if (it != entries.end() && it->second.valid) {
        return it->second.mac;
    }
    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    auto it = entries.find(ip);
    if (it == entries.end()) {
        // Create a pending ARP entry with the packet queued.
        ArpEntry entry;
        entry.valid = false;
        entry.timeAdded = now;
        entry.lastRequestSent = now;
        entry.requestCount = 1;  // First ARP request sent now.
        entry.pendingPackets.push_back({packet, iface});
        entries[ip] = std::move(entry);
        spdlog::info("Sending initial ARP request for IP: {}", ip);
        // *** ARP REQUEST PACKET GENERATION NOT IMPLEMENTED ***
        // Example:
        // Packet arpReq = buildArpRequest(ip);
        // packetSender->sendPacket(arpReq, iface);
    } else {
        if (!it->second.valid) {
            it->second.pendingPackets.push_back({packet, iface});
        } else {
            // If entry is valid, send the packet immediately.
            packetSender->sendPacket(packet, iface);
        }
    }
}
