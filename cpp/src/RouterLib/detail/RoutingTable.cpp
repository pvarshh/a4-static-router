#include "RoutingTable.h"
#include <arpa/inet.h>
#include <iostream>

using namespace RouterLib::detail;

// Helper to parse an IPv4 address string to uint32_t (network byte order)
static uint32_t parseIPv4(const std::string& ipStr) {
    uint32_t result;
    if (inet_pton(AF_INET, ipStr.c_str(), &result) != 1) {
        throw std::runtime_error("Invalid IP address format: " + ipStr);
    }
    // inet_pton already gives result in network byte order
    return result;
}

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open routing table file: " + routingTablePath.string());
    }
    std::string line;
    // Each line format: prefix next_hop netmask interface
    while (std::getline(file, line)) {
        // Skip empty or comment lines (if any)
        if(line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string prefixStr, nextHopStr, maskStr, iface;
        if (!(iss >> prefixStr >> nextHopStr >> maskStr >> iface)) {
            continue; // skip line if format is not as expected
        }
        RoutingEntry entry;
        entry.dest = parseIPv4(prefixStr);
        entry.gateway = parseIPv4(nextHopStr);
        entry.mask = parseIPv4(maskStr);
        entry.iface = iface;
        entries.push_back(entry);
        // Also prepare interface map entry with name if not present
        if (interfaces.find(iface) == interfaces.end()) {
            RoutingInterface rif;
            rif.name = iface;
            // initialize MAC as zeros and IP as 0 for now, will be set later via setRoutingInterface
            rif.mac = {0,0,0,0,0,0};
            rif.ip = 0;
            interfaces[iface] = rif;
        }
    }
    file.close();
    // It may be useful to sort entries by mask length (descending) for longest prefix match
    std::sort(entries.begin(), entries.end(), [](const RoutingEntry& a, const RoutingEntry& b){
        // Compare mask lengths by number of bits set (assuming mask is contiguous ones)
        auto countBits = [](uint32_t mask) {
            uint32_t m = ntohl(mask); // convert mask to host for counting bits
            unsigned int count = 0;
            while (m) {
                count += (m & 1);
                m >>= 1;
            }
            return count;
        };
        unsigned int a_bits = countBits(a.mask);
        unsigned int b_bits = countBits(b.mask);
        if (a_bits != b_bits) return a_bits > b_bits;
        // If equal length, tie-break by destination value (not crucial to correctness)
        return ntohl(a.dest) < ntohl(b.dest);
    });
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    // The 'ip' provided is expected to be in network byte order (consistent with stored entries)
    std::optional<RoutingEntry> bestMatch = std::nullopt;
    unsigned int bestMaskBits = 0;
    for (const auto& entry : entries) {
        // Check if (ip & entry.mask) == (entry.dest & entry.mask) (longest prefix match)&#8203;:contentReference[oaicite:0]{index=0}
        if ((ip & entry.mask) == (entry.dest & entry.mask)) {
            // Count bits in this mask
            uint32_t mask_host = ntohl(entry.mask);
            unsigned int maskBits = 0;
            while(mask_host) {
                maskBits += (mask_host & 1);
                mask_host >>= 1;
            }
            if (!bestMatch || maskBits > bestMaskBits) {
                bestMaskBits = maskBits;
                bestMatch = entry;
            }
        }
    }
    return bestMatch;
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    auto it = interfaces.find(iface);
    if (it == interfaces.end()) {
        throw std::runtime_error("Interface not found: " + iface);
    }
    return it->second;
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    // Ensure interface exists in map (if not, create it)
    RoutingInterface rif;
    rif.name = iface;
    rif.mac = mac;
    rif.ip = ip;
    interfaces[iface] = rif;
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const {
    return interfaces;
}
