#ifndef ROUTERLIB_DETAIL_ROUTINGTABLE_H
#define ROUTERLIB_DETAIL_ROUTINGTABLE_H

#include <vector>
#include <unordered_map>
#include <string>
#include <optional>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <arpa/inet.h>  // for inet_pton, htonl

#include "IRoutingTable.h"

namespace RouterLib::detail {

class RoutingTable : public IRoutingTable {
public:
    // Construct a routing table by reading from a file.
    RoutingTable(const std::filesystem::path& routingTablePath);
    virtual ~RoutingTable() = default;

    std::optional<RoutingEntry> getRoutingEntry(ip_addr ip) override;
    RoutingInterface getRoutingInterface(const std::string& iface) override;
    void setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) override;
    const std::unordered_map<std::string, RoutingInterface>& getRoutingInterfaces() const override;

private:
    std::vector<RoutingEntry> entries;
    std::unordered_map<std::string, RoutingInterface> interfaces;
};

} // namespace RouterLib::detail

#endif // ROUTERLIB_DETAIL_ROUTINGTABLE_H
