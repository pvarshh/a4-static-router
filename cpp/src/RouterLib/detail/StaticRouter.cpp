#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
    , packetSender(packetSender)
    , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below
    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    if (ether_type == ETHERTYPE_ARP) {
        arp_hdr_t* arp_hdr = reinterpret_cast<arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint16_t arp_op = ntohs(arp_hdr->arp_op);

        if (arp_op == ARP_REQUEST) {
            spdlog::info("Received ARP request on interface {}.", iface);
            // Pseudo-code: If the ARP request's target IP matches one of our interface IPs,
            // build an ARP reply packet and send it.
            Packet arpReply = buildArpReply(packet, iface);
            packetSender->sendPacket(arpReply, iface);
        } 
        else if (arp_op == ARP_REPLY) {
            uint32_t sender_ip = arp_hdr->arp_sip;
            mac_addr sender_mac;
            std::memcpy(sender_mac, arp_hdr->arp_sha, ETHER_ADDR_LEN);
            spdlog::info("Received ARP reply; updating ARP cache for IP: {}", sender_ip);
            arpCache->addEntry(sender_ip, sender_mac);
        }
        return;
    }
    else if (ether_type == ETHERTYPE_IP) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(ip_hdr_t)) {
            spdlog::error("Packet is too small to contain an IP header.");
            return;
        }
        ip_hdr_t* ip_hdr = reinterpret_cast<ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        // Verify IP checksum.
        if (ip_checksum(ip_hdr, ip_hdr->ip_hl * 4) != 0) {
            spdlog::error("Invalid IP checksum.");
            return;
        }

        uint32_t dest_ip = ip_hdr->ip_dst;
        bool isForRouter = false;
        for (const auto& entry : routingTable->getRoutingInterfaces()) {
            if (entry.second.ip == dest_ip) {
                isForRouter = true;
                break;
            }
        }
        if (isForRouter) {
            // Packet is destined for the router.
            if (ip_hdr->ip_p == IPPROTO_ICMP) {
                icmp_hdr_t* icmp_hdr = reinterpret_cast<icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + ip_hdr->ip_hl * 4);
                if (icmp_hdr->icmp_type == ICMP_ECHO) {
                    spdlog::info("Received ICMP echo request to router; sending echo reply.");
                    // Pseudo-code: Build an ICMP echo reply packet.
                    Packet icmpReply = buildIcmpEchoReply(packet);
                    packetSender->sendPacket(icmpReply, iface);
                }
            }
            else {
                spdlog::info("Received TCP/UDP packet to router; sending ICMP port unreachable.");
                // Pseudo-code: Build an ICMP port unreachable packet.
                Packet portUnreach = buildIcmpPortUnreachable(packet);
                packetSender->sendPacket(portUnreach, iface);
            }
            return;
        }
        else {
            // Forward the packet.
            if (ip_hdr->ip_ttl <= 1) {
                spdlog::info("TTL expired; sending ICMP time exceeded.");
                // Pseudo-code: Build and send an ICMP time exceeded packet.
                Packet timeExceeded = buildIcmpTimeExceeded(packet);
                packetSender->sendPacket(timeExceeded, iface);
                return;
            }
            ip_hdr->ip_ttl -= 1;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = ip_checksum(ip_hdr, ip_hdr->ip_hl * 4);

            auto routeOpt = routingTable->getRoutingEntry(dest_ip);
            if (!routeOpt.has_value()) {
                spdlog::error("No routing entry found for destination IP: {}", dest_ip);
                // Pseudo-code: Build and send an ICMP destination net unreachable packet.
                Packet destUnreach = buildIcmpDestUnreachable(packet);
                packetSender->sendPacket(destUnreach, iface);
                return;
            }
            RoutingEntry route = routeOpt.value();
            // Determine next hop: use the gateway if nonzero, otherwise the destination itself.
            uint32_t next_hop = (route.gateway != 0) ? route.gateway : dest_ip;

            auto macOpt = arpCache->getEntry(next_hop);
            if (macOpt.has_value()) {
                mac_addr nextHopMac = macOpt.value();
                // Update the Ethernet header: set destination MAC to the next hop's MAC.
                std::memcpy(eth_hdr->ether_dhost, nextHopMac, ETHER_ADDR_LEN);
                // Set source MAC to that of the outgoing interface.
                RoutingInterface rIface = routingTable->getRoutingInterface(route.iface);
                std::memcpy(eth_hdr->ether_shost, rIface.mac, ETHER_ADDR_LEN);
                spdlog::info("Forwarding IP packet to next hop via interface {}.", route.iface);
                packetSender->sendPacket(packet, route.iface);
            }
            else {
                spdlog::info("Next hop MAC not found in ARP cache; queuing packet and sending ARP request.");
                arpCache->queuePacket(next_hop, packet, route.iface);
            }
        }
    } else {
        spdlog::error("Unknown Ethernet type: {}", ether_type);
    }
}