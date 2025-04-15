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
        std::string dest, gateway, mask, iface;
        iss >> dest >> gateway >> mask >> iface;

        uint32_t dest_ip, gateway_ip, subnet_mask;

        if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
            inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
            inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
            }

        routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
    }
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    // TODO: Your code below

    std::optional<RoutingEntry> bestEntry;
    int bestMaskLength = -1;  // Largest number of bits matched in the netmask.

    for (const auto &entry : routingEntries) {
        // A match: destination IP masked by the entry's netmask equals the entry's network.
        if ((ip & entry.subnet_mask) == (entry.dest_ip & entry.subnet_mask)) {
            // Count the number of bits set (mask length) in the subnet mask.
            uint32_t mask = entry.subnet_mask;
            int bits = 0;
            while (mask) {
                bits += (mask & 1);
                mask >>= 1;
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

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}
