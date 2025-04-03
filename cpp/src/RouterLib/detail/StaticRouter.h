#ifndef ROUTERLIB_DETAIL_STATICROUTER_H
#define ROUTERLIB_DETAIL_STATICROUTER_H

#include <memory>
#include <string>
#include <vector>

#include "IStaticRouter.h"
#include "IRoutingTable.h"
#include "IPacketSender.h"
#include "ArpCache.h"

namespace RouterLib::detail {

class StaticRouter : public IStaticRouter {
public:
    StaticRouter(std::unique_ptr<ArpCache> arpCache,
                 std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);
    ~StaticRouter() = default;
    void handlePacket(std::vector<uint8_t> packet, std::string iface) override;
private:
    std::unique_ptr<ArpCache> arpCache;
    std::shared_ptr<IRoutingTable> rt;
    std::shared_ptr<IPacketSender> sender;
};

} // namespace RouterLib::detail

#endif // ROUTERLIB_DETAIL_STATICROUTER_H
