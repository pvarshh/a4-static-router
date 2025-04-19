#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

// Define a simple IP checksum function if not provided elsewhere.
static uint16_t ip_checksum(const void* vdata, size_t length) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(vdata);
    uint32_t acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word = (data[i] << 8) | data[i+1];
        acc += word;
        if (acc > 0xFFFF)
            acc = (acc & 0xFFFF) + (acc >> 16);
    }
    if (length & 1) {
        uint16_t word = data[length - 1] << 8;
        acc += word;
        if (acc > 0xFFFF)
            acc = (acc & 0xFFFF) + (acc >> 16);
    }
    return ~acc;
}

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ARP_REQUEST
#define ARP_REQUEST 1
#endif
#ifndef ARP_REPLY
#define ARP_REPLY 2
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
    , packetSender(packetSender)
    , arpCache(std::move(arpCache))
{
}

// Helper functions for each of the replies:

void swapMacAddresses(sr_ethernet_hdr_t* hdr) {
    uint8_t temp[ETHER_ADDR_LEN];
    std::memcpy(temp, hdr->ether_dhost, ETHER_ADDR_LEN);
    std::memcpy(hdr->ether_dhost, hdr->ether_shost, ETHER_ADDR_LEN);
    std::memcpy(hdr->ether_shost, temp, ETHER_ADDR_LEN);
}

void swapIpAddresses(sr_ip_hdr_t* ip_hdr) {
    uint32_t tmp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = tmp;
}

void updateIpChecksum(sr_ip_hdr_t* ip_hdr) {
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
}

//Again, this could be part of the function and not as its standalone stuff. I will fix this later and make it more modular.
std::vector<uint8_t> buildArpReply(const sr_arp_hdr_t* request, const mac_addr& our_mac, uint32_t our_ip) {
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* arp = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    std::memcpy(eth->ether_dhost, request->ar_sha, ETHER_ADDR_LEN);
    std::memcpy(eth->ether_shost, our_mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = 4;
    arp->ar_op  = htons(ARP_REPLY);

    std::memcpy(arp->ar_sha, our_mac.data(), ETHER_ADDR_LEN);
    arp->ar_sip = our_ip;
    std::memcpy(arp->ar_tha, request->ar_sha, ETHER_ADDR_LEN);
    arp->ar_tip = request->ar_sip;

    return packet;
}

std::vector<uint8_t> buildIcmpEchoReply(const std::vector<uint8_t>& request) {
    // We have this for now, but we should receive them as an argument later on
    auto eth_hdr = reinterpret_cast<const sr_ethernet_hdr_t*>(request.data());
    auto ip_hdr = reinterpret_cast<const sr_ip_hdr_t*>(request.data() + sizeof(sr_ethernet_hdr_t));
    auto icmp_hdr = reinterpret_cast<const sr_icmp_hdr_t*>(
        request.data() + sizeof(sr_ethernet_hdr_t) + ip_hdr->ip_hl * 4);

    std::vector<uint8_t> reply(request);

    // Swaps the MAC addresses
    sr_ethernet_hdr_t* new_eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
    std::swap_ranges(new_eth_hdr->ether_dhost, new_eth_hdr->ether_dhost + ETHER_ADDR_LEN,
                     new_eth_hdr->ether_shost);

    // Swaps the IPs
    sr_ip_hdr_t* new_ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(reply.data() + sizeof(sr_ethernet_hdr_t));
    uint32_t temp_ip = new_ip_hdr->ip_src;
    new_ip_hdr->ip_src = new_ip_hdr->ip_dst;
    new_ip_hdr->ip_dst = temp_ip;

    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

    // Sets ICMP type to echo reply
    // I hope this works tho
    sr_icmp_hdr_t* new_icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(
        reply.data() + sizeof(sr_ethernet_hdr_t) + new_ip_hdr->ip_hl * 4);
    new_icmp_hdr->icmp_type = 0;
    new_icmp_hdr->icmp_sum = 0;
    int icmp_len = ntohs(new_ip_hdr->ip_len) - new_ip_hdr->ip_hl * 4;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_len);

    return reply;
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    if (ether_type == ETHERTYPE_ARP) {
        // Use sr_arp_hdr_t; note the field names defined in protocol.h: ar_op, ar_sip, ar_sha.
        sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint16_t arp_op = ntohs(arp_hdr->ar_op);

        if (arp_op == ARP_REQUEST) {
            spdlog::info("Received ARP request on interface {}.", iface);
            // TODO: If the ARP request target IP matches one of our interface IPs,
            // build an ARP reply packet and send it.
            // Example (pseudo-code):
            // Packet arpReply = buildArpReply(packet, iface);
            // packetSender->sendPacket(arpReply, iface);
        } else if (arp_op == ARP_REPLY) {
            uint32_t sender_ip = arp_hdr->ar_sip;
            mac_addr sender_mac;
            std::memcpy(sender_mac.data(), arp_hdr->ar_sha, ETHER_ADDR_LEN);
            spdlog::info("Received ARP reply; updating ARP cache for IP: {}", sender_ip);
            arpCache->addEntry(sender_ip, sender_mac);
        }
        return;
    }
    else if (ether_type == ETHERTYPE_IP) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            spdlog::error("Packet is too small to contain an IP header.");
            return;
        }
        sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        // Verify the IP checksum.
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
                sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(
                packet.data() + sizeof(sr_ethernet_hdr_t) + ip_hdr->ip_hl * 4);
                if (icmp_hdr->icmp_type == ICMP_ECHO) {
                    spdlog::info("Received ICMP echo request to router; sending echo reply.");
                    // TODO: Build an ICMP echo reply packet and send it.
                    // Example (pseudo-code):
                    Packet icmpReply = buildIcmpEchoReply(packet);
                    packetSender->sendPacket(icmpReply, iface);
                }
            } else {
                spdlog::info("Received TCP/UDP packet to router; sending ICMP port unreachable.");
                // TODO: Build an ICMP port unreachable packet and send it.
                // Example (pseudo-code):
                // Packet portUnreach = buildIcmpPortUnreachable(packet);
                // packetSender->sendPacket(portUnreach, iface);
            }
            return;
        } else {
            // Forward the packet.
            if (ip_hdr->ip_ttl <= 1) {
                spdlog::info("TTL expired; sending ICMP time exceeded.");
                // TODO: Build an ICMP time exceeded packet and send it.
                // Example (pseudo-code):
                // Packet timeExceeded = buildIcmpTimeExceeded(packet);
                // packetSender->sendPacket(timeExceeded, iface);
                return;
            }
            ip_hdr->ip_ttl -= 1;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = ip_checksum(ip_hdr, ip_hdr->ip_hl * 4);

            auto routeOpt = routingTable->getRoutingEntry(dest_ip);
            if (!routeOpt.has_value()) {
                spdlog::error("No routing entry found for destination IP: {}", dest_ip);
                // TODO: Build an ICMP destination unreachable packet and send it.
                // Example (pseudo-code):
                // Packet destUnreach = buildIcmpDestUnreachable(packet);
                // packetSender->sendPacket(destUnreach, iface);
                return;
            }
            RoutingEntry route = routeOpt.value();
            // Determine next-hop: if the gateway field is nonzero, use it; otherwise, use dest_ip.
            uint32_t next_hop = (route.gateway != 0) ? route.gateway : dest_ip;

            auto macOpt = arpCache->getEntry(next_hop);
            if (macOpt.has_value()) {
                mac_addr nextHopMac = macOpt.value();
                // Update the Ethernet header: set destination MAC to the next hop's MAC.
                std::memcpy(eth_hdr->ether_dhost, nextHopMac.data(), ETHER_ADDR_LEN);
                // Set source MAC to that of the outgoing interface.
                RoutingInterface rIface = routingTable->getRoutingInterface(route.iface);
                std::memcpy(eth_hdr->ether_shost, rIface.mac.data(), ETHER_ADDR_LEN);
                spdlog::info("Forwarding IP packet to next hop via interface {}.", route.iface);
                packetSender->sendPacket(packet, route.iface);
            } else {
                spdlog::info("Next hop MAC not found in ARP cache; queuing packet and sending ARP request.");
                arpCache->queuePacket(next_hop, packet, route.iface);
            }
        }
    } else {
        spdlog::error("Unknown Ethernet type: {}", ether_type);
    }
}
