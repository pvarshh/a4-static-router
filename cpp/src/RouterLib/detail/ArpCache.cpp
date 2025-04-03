#include "StaticRouter.h"
#include <arpa/inet.h>
#include <cstring>

using namespace RouterLib::detail;

StaticRouter::StaticRouter(std::unique_ptr<ArpCache> arpCache,
                           std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : arpCache(std::move(arpCache)), rt(routingTable), sender(packetSender) {}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    if (packet.size() < 14) {
        return; // too short for Ethernet header
    }
    // Parse Ethernet header
    uint16_t etherType;
    std::memcpy(&etherType, packet.data()+12, 2);
    etherType = ntohs(etherType);
    if (etherType == 0x0806) {
        // ARP packet
        arpCache->handleArpRequest(packet, iface);
        arpCache->handleArpReply(packet);
        // No further processing for ARP frames
    } else if (etherType == 0x0800) {
        // IPv4 packet
        if (packet.size() < 34) {
            return; // not enough bytes for IP header
        }
        uint8_t* ipHeader = packet.data() + 14;
        // Verify IP header checksum
        uint16_t originalCksum;
        std::memcpy(&originalCksum, ipHeader + 10, 2);
        std::memcpy(ipHeader + 10, "\x00\x00", 2);  // set checksum field to 0 for calc
        uint32_t sum = 0;
        uint8_t ihl = ipHeader[0] & 0x0F;
        uint16_t headerLenBytes = ihl * 4;
        if (packet.size() < 14 + headerLenBytes) {
            return;
        }
        for (uint16_t i = 0; i < headerLenBytes; i += 2) {
            uint16_t word;
            std::memcpy(&word, ipHeader + i, 2);
            sum += ntohs(word);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        uint16_t computed = ~((uint16_t)sum);
        std::memcpy(ipHeader + 10, &originalCksum, 2);  // restore
        if (computed != 0xFFFF) {
            // Drop packet with bad checksum
            return;
        }
        // Retrieve destination IP from IP header
        uint32_t destIP;
        std::memcpy(&destIP, ipHeader + 16, 4);
        // Check if destination IP is one of this router's interfaces
        bool isForRouter = false;
        for (auto& [name, rif] : rt->getRoutingInterfaces()) {
            if (rif.ip == destIP) {
                isForRouter = true;
                break;
            }
        }
        uint8_t protocol = ipHeader[9];
        if (isForRouter) {
            // Packet intended for router
            if (protocol == 1) { // ICMP
                if (packet.size() < 14 + headerLenBytes + 8) {
                    return;
                }
                uint8_t* icmpHeader = ipHeader + headerLenBytes;
                uint8_t icmpType = icmpHeader[0];
                uint8_t icmpCode = icmpHeader[1];
                if (icmpType == 8 && icmpCode == 0) {
                    // Echo request -> prepare Echo reply (ICMP Type 0)&#8203;:contentReference[oaicite:2]{index=2}
                    mac_addr routerMac = rt->getRoutingInterface(iface).mac;
                    mac_addr origMac;
                    std::copy(packet.begin()+6, packet.begin()+12, origMac.begin());
                    // Swap Ethernet src/dst
                    std::copy(origMac.begin(), origMac.end(), packet.begin());      // dest MAC = original src MAC
                    std::copy(routerMac.begin(), routerMac.end(), packet.begin()+6); // src MAC = router's MAC
                    // Swap IP src/dst
                    uint32_t srcIP, dstIP;
                    std::memcpy(&srcIP, ipHeader + 12, 4);
                    std::memcpy(&dstIP, ipHeader + 16, 4);
                    std::memcpy(ipHeader + 12, &dstIP, 4);
                    std::memcpy(ipHeader + 16, &srcIP, 4);
                    // Prepare ICMP echo reply
                    icmpHeader[0] = 0; // type = Echo Reply
                    // Recompute ICMP checksum
                    icmpHeader[2] = 0;
                    icmpHeader[3] = 0;
                    uint16_t totalLen;
                    std::memcpy(&totalLen, ipHeader + 2, 2);
                    totalLen = ntohs(totalLen);
                    uint16_t icmpLen = totalLen - headerLenBytes;
                    uint32_t icmpSum = 0;
                    for (uint16_t i = 0; i < icmpLen; i += 2) {
                        uint16_t word = 0;
                        std::memcpy(&word, icmpHeader + i, (i+1 < icmpLen ? 2 : 1));
                        icmpSum += ntohs(word);
                    }
                    while (icmpSum >> 16) {
                        icmpSum = (icmpSum & 0xFFFF) + (icmpSum >> 16);
                    }
                    uint16_t icmpChk = htons((uint16_t)~icmpSum);
                    std::memcpy(icmpHeader + 2, &icmpChk, 2);
                    // Recompute IP header for reply
                    ipHeader[8] = 64;  // reset TTL
                    ipHeader[9] = 1;   // protocol = ICMP
                    std::memset(ipHeader + 10, 0, 2);
                    uint32_t ipSum = 0;
                    for (uint16_t i = 0; i < headerLenBytes; i += 2) {
                        uint16_t word;
                        std::memcpy(&word, ipHeader + i, 2);
                        ipSum += ntohs(word);
                    }
                    while (ipSum >> 16) {
                        ipSum = (ipSum & 0xFFFF) + (ipSum >> 16);
                    }
                    uint16_t ipChk = htons((uint16_t)~ipSum);
                    std::memcpy(ipHeader + 10, &ipChk, 2);
                    // Send ICMP Echo Reply out the incoming interface
                    sender->sendPacket(packet, iface);
                }
            } else if (protocol == 6 || protocol == 17) {
                // TCP or UDP sent to router (likely a traceroute packet) - send ICMP Port Unreachable
                uint8_t ihl = ipHeader[0] & 0x0F;
                uint16_t ipHeaderLen = ihl * 4;
                if (packet.size() < 14 + ipHeaderLen + 8) {
                    return;
                }
                uint32_t origSrcIP, origDstIP;
                std::memcpy(&origSrcIP, ipHeader + 12, 4);
                std::memcpy(&origDstIP, ipHeader + 16, 4);
                RoutingInterface inIntf = rt->getRoutingInterface(iface);
                mac_addr routerMac = inIntf.mac;
                uint32_t routerIP = inIntf.ip;
                mac_addr origSrcMac;
                std::copy(packet.begin()+6, packet.begin()+12, origSrcMac.begin());
                Packet icmpFrame;
                size_t icmpDataLen = ipHeaderLen + 8;
                icmpFrame.resize(14 + 20 + 8 + icmpDataLen);
                uint8_t* buf = icmpFrame.data();
                // Ethernet header
                std::copy(origSrcMac.begin(), origSrcMac.end(), buf);        // dest MAC = original sender MAC
                std::copy(routerMac.begin(), routerMac.end(), buf + 6);      // src MAC = router's MAC
                uint16_t ethTypeIP = htons(0x0800);
                std::memcpy(buf + 12, &ethTypeIP, 2);
                // IP header for ICMP
                uint8_t* outIp = buf + 14;
                outIp[0] = 0x45;
                outIp[1] = 0x00;
                uint16_t totalLen = htons(20 + 8 + icmpDataLen);
                std::memcpy(outIp + 2, &totalLen, 2);
                uint16_t ipId = 0;
                std::memcpy(outIp + 4, &ipId, 2);
                uint16_t offset = 0;
                std::memcpy(outIp + 6, &offset, 2);
                outIp[8] = 64;
                outIp[9] = 1;
                std::memcpy(outIp + 12, &routerIP, 4);
                std::memcpy(outIp + 16, &origSrcIP, 4);
                outIp[10] = 0; outIp[11] = 0;
                uint32_t sumIP = 0;
                for(int i=0; i<20; i+=2){
                    uint16_t w;
                    std::memcpy(&w, outIp+i, 2);
                    sumIP += ntohs(w);
                }
                while(sumIP >> 16){
                    sumIP = (sumIP & 0xFFFF) + (sumIP >> 16);
                }
                uint16_t outIpChk = htons((uint16_t)~sumIP);
                std::memcpy(outIp + 10, &outIpChk, 2);
                // ICMP header and data
                uint8_t* icmpOut = buf + 14 + 20;
                icmpOut[0] = 3;  // Type 3 (Destination Unreachable)
                icmpOut[1] = 3;  // Code 3 (Port Unreachable)
                icmpOut[2] = 0; icmpOut[3] = 0;
                std::memset(icmpOut + 4, 0, 4);
                std::memcpy(icmpOut + 8, ipHeader, icmpDataLen);
                uint32_t sumI = 0;
                size_t icmpLen = 8 + icmpDataLen;
                for(size_t i=0; i<icmpLen; i+=2){
                    uint16_t w = 0;
                    std::memcpy(&w, icmpOut + i, (i+1 < icmpLen ? 2 : 1));
                    sumI += ntohs(w);
                }
                while(sumI >> 16){
                    sumI = (sumI & 0xFFFF) + (sumI >> 16);
                }
                uint16_t icmpChk = htons((uint16_t)~sumI);
                std::memcpy(icmpOut + 2, &icmpChk, 2);
                sender->sendPacket(icmpFrame, iface);
                return;
            }
        } else {
            // Packet needs forwarding (destination not this router)
            // Check TTL
            uint8_t ttl = ipHeader[8];
            if (ttl <= 1) {
                // TTL expired - send ICMP Time Exceeded
                uint8_t ihl2 = ipHeader[0] & 0x0F;
                uint16_t ipHeaderLen2 = ihl2 * 4;
                if (packet.size() < 14 + ipHeaderLen2 + 8) {
                    return;
                }
                uint32_t origSrcIP2;
                std::memcpy(&origSrcIP2, ipHeader + 12, 4);
                RoutingInterface inIntf2 = rt->getRoutingInterface(iface);
                mac_addr routerMac2 = inIntf2.mac;
                uint32_t routerIP2 = inIntf2.ip;
                mac_addr origSrcMac2;
                std::copy(packet.begin()+6, packet.begin()+12, origSrcMac2.begin());
                Packet icmpFrame2;
                size_t icmpDataLen2 = ipHeaderLen2 + 8;
                icmpFrame2.resize(14 + 20 + 8 + icmpDataLen2);
                uint8_t* buf2 = icmpFrame2.data();
                // Ethernet header
                std::copy(origSrcMac2.begin(), origSrcMac2.end(), buf2);
                std::copy(routerMac2.begin(), routerMac2.end(), buf2 + 6);
                uint16_t ethTypeIP2 = htons(0x0800);
                std::memcpy(buf2 + 12, &ethTypeIP2, 2);
                // IP header for ICMP
                uint8_t* ipOut2 = buf2 + 14;
                ipOut2[0] = 0x45;
                ipOut2[1] = 0x00;
                uint16_t totLen2 = htons(20 + 8 + icmpDataLen2);
                std::memcpy(ipOut2 + 2, &totLen2, 2);
                uint16_t ipId2 = 0;
                std::memcpy(ipOut2 + 4, &ipId2, 2);
                uint16_t off2 = 0;
                std::memcpy(ipOut2 + 6, &off2, 2);
                ipOut2[8] = 64;
                ipOut2[9] = 1;
                std::memcpy(ipOut2 + 12, &routerIP2, 4);
                std::memcpy(ipOut2 + 16, &origSrcIP2, 4);
                ipOut2[10] = 0; ipOut2[11] = 0;
                uint32_t sumIP2 = 0;
                for(int i=0; i<20; i+=2){
                    uint16_t w;
                    std::memcpy(&w, ipOut2+i, 2);
                    sumIP2 += ntohs(w);
                }
                while(sumIP2 >> 16){
                    sumIP2 = (sumIP2 & 0xFFFF) + (sumIP2 >> 16);
                }
                uint16_t ipChk2 = htons((uint16_t)~sumIP2);
                std::memcpy(ipOut2 + 10, &ipChk2, 2);
                // ICMP header
                uint8_t* icmpOut2 = buf2 + 14 + 20;
                icmpOut2[0] = 11;  // Type 11 (Time Exceeded)
                icmpOut2[1] = 0;   // Code 0
                icmpOut2[2] = 0; icmpOut2[3] = 0;
                std::memset(icmpOut2 + 4, 0, 4);
                std::memcpy(icmpOut2 + 8, ipHeader, icmpDataLen2);
                uint32_t sumIc2 = 0;
                size_t icmpLen2 = 8 + icmpDataLen2;
                for(size_t i=0; i<icmpLen2; i+=2){
                    uint16_t w = 0;
                    std::memcpy(&w, icmpOut2+i, (i+1 < icmpLen2 ? 2 : 1));
                    sumIc2 += ntohs(w);
                }
                while(sumIc2 >> 16){
                    sumIc2 = (sumIc2 & 0xFFFF) + (sumIc2 >> 16);
                }
                uint16_t icmpChk2 = htons((uint16_t)~sumIc2);
                std::memcpy(icmpOut2 + 2, &icmpChk2, 2);
                sender->sendPacket(icmpFrame2, iface);
                return;
            }
            // Decrement TTL and update checksum
            uint8_t newTTL = ttl - 1;
            ipHeader[8] = newTTL;
            std::memset(ipHeader + 10, 0, 2);
            uint32_t newSum = 0;
            for (uint16_t i = 0; i < headerLenBytes; i += 2) {
                uint16_t word;
                std::memcpy(&word, ipHeader + i, 2);
                newSum += ntohs(word);
            }
            while (newSum >> 16) {
                newSum = (newSum & 0xFFFF) + (newSum >> 16);
            }
            uint16_t newCksum = htons((uint16_t)~newSum);
            std::memcpy(ipHeader + 10, &newCksum, 2);
            // Find route for destination
            auto routeEntryOpt = rt->getRoutingEntry(destIP);
            if (!routeEntryOpt.has_value()) {
                // No route -> ICMP Net Unreachable
                uint8_t ihln = ipHeader[0] & 0x0F;
                uint16_t ipHeaderLenn = ihln * 4;
                if (packet.size() < 14 + ipHeaderLenn + 8) {
                    return;
                }
                uint32_t origSrcIPn;
                std::memcpy(&origSrcIPn, ipHeader + 12, 4);
                RoutingInterface inIntfn = rt->getRoutingInterface(iface);
                mac_addr routerMacn = inIntfn.mac;
                uint32_t routerIPn = inIntfn.ip;
                mac_addr origSrcMacn;
                std::copy(packet.begin()+6, packet.begin()+12, origSrcMacn.begin());
                Packet icmpFramen;
                size_t icmpDataLenn = ipHeaderLenn + 8;
                icmpFramen.resize(14 + 20 + 8 + icmpDataLenn);
                uint8_t* bufn = icmpFramen.data();
                // Ethernet
                std::copy(origSrcMacn.begin(), origSrcMacn.end(), bufn);
                std::copy(routerMacn.begin(), routerMacn.end(), bufn + 6);
                uint16_t ethTypeIPn = htons(0x0800);
                std::memcpy(bufn + 12, &ethTypeIPn, 2);
                // IP header
                uint8_t* ipOutn = bufn + 14;
                ipOutn[0] = 0x45;
                ipOutn[1] = 0x00;
                uint16_t totLenn = htons(20 + 8 + icmpDataLenn);
                std::memcpy(ipOutn + 2, &totLenn, 2);
                uint16_t ipIdn = 0;
                std::memcpy(ipOutn + 4, &ipIdn, 2);
                uint16_t offn = 0;
                std::memcpy(ipOutn + 6, &offn, 2);
                ipOutn[8] = 64;
                ipOutn[9] = 1;
                std::memcpy(ipOutn + 12, &routerIPn, 4);
                std::memcpy(ipOutn + 16, &origSrcIPn, 4);
                ipOutn[10] = 0; ipOutn[11] = 0;
                uint32_t sumIPn = 0;
                for(int i=0; i<20; i+=2){
                    uint16_t w;
                    std::memcpy(&w, ipOutn+i, 2);
                    sumIPn += ntohs(w);
                }
                while(sumIPn >> 16){
                    sumIPn = (sumIPn & 0xFFFF) + (sumIPn >> 16);
                }
                uint16_t ipChkn = htons((uint16_t)~sumIPn);
                std::memcpy(ipOutn + 10, &ipChkn, 2);
                // ICMP header
                uint8_t* icmpOutn = bufn + 14 + 20;
                icmpOutn[0] = 3;
                icmpOutn[1] = 0;
                icmpOutn[2] = 0; icmpOutn[3] = 0;
                std::memset(icmpOutn + 4, 0, 4);
                std::memcpy(icmpOutn + 8, ipHeader, icmpDataLenn);
                uint32_t sumIn = 0;
                size_t icmpLenn = 8 + icmpDataLenn;
                for(size_t i=0; i<icmpLenn; i+=2){
                    uint16_t w = 0;
                    std::memcpy(&w, icmpOutn+i, (i+1<icmpLenn ? 2 : 1));
                    sumIn += ntohs(w);
                }
                while(sumIn >> 16){
                    sumIn = (sumIn & 0xFFFF) + (sumIn >> 16);
                }
                uint16_t icmpChkn = htons((uint16_t)~sumIn);
                std::memcpy(icmpOutn + 2, &icmpChkn, 2);
                sender->sendPacket(icmpFramen, iface);
                return;
            }
            RoutingEntry route = routeEntryOpt.value();
            std::string outIface = route.iface;
            ip_addr nextHop = route.gateway;
            if (nextHop == 0) {
                nextHop = destIP;
            }
            // Check ARP cache for nextHop
            auto macOpt = arpCache->lookup(nextHop);
            if (macOpt.has_value()) {
                mac_addr nextHopMac = macOpt.value();
                // Update Ethernet addresses for forwarding
                std::copy(nextHopMac.begin(), nextHopMac.end(), packet.begin());       // dest MAC = nextHop MAC
                mac_addr outMac = rt->getRoutingInterface(outIface).mac;
                std::copy(outMac.begin(), outMac.end(), packet.begin()+6);            // src MAC = router's MAC on outIface
                // Forward packet out the outgoing interface
                sender->sendPacket(packet, outIface);
            } else {
                // Need ARP - queue packet and send ARP request
                arpCache->queueRequest(nextHop, std::move(packet), outIface, iface);
            }
        }
        // Periodically tick the ARP cache for timeouts and retries
        arpCache->tick();
    }
}
