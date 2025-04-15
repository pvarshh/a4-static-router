#include "RoutingTable.h"

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    if (!std::filesystem::exists(routingTablePath)) {
        throw std::runtime_error("Routing table file does not exist");
    }
    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open routing table file");
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream iss(line);
        std::string dest_str, gateway_str, mask_str, iface;
        iss >> dest_str >> gateway_str >> mask_str >> iface;
        uint32_t dest, gateway, mask;
        if (inet_pton(AF_INET, dest_str.c_str(), &dest) != 1 ||
            inet_pton(AF_INET, gateway_str.c_str(), &gateway) != 1 ||
            inet_pton(AF_INET, mask_str.c_str(), &mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
        }
        routingEntries.push_back({dest, gateway, mask, iface});
    }
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    std::optional<RoutingEntry> bestEntry;
    int bestMaskLength = -1;  // Largest mask length matched.
    for (const auto &entry : routingEntries) {
        // Compare ip masked by entry.mask with entry.dest masked by entry.mask.
        if ((ip & entry.mask) == (entry.dest & entry.mask)) {
            // Count the number of one bits in the mask.
            uint32_t maskVal = entry.mask;
            int bits = 0;
            while (maskVal) {
                bits += (maskVal & 1);
                maskVal >>= 1;
            }
            if (bits > bestMaskLength) {
                bestMaskLength = bits;
                bestEntry = entry;
            }
        }
    }
    return bestEntry;
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const {
    return routingInterfaces;
}
