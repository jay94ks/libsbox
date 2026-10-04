#include <sbox/net/ipam.hpp>
#include <sbox/net/lock.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>

namespace sbox {
namespace net {

    namespace {

        constexpr uint64_t MAX_SCAN = uint64_t(1) << 22;
        constexpr uint64_t MAX_POOL_SPLITS = uint64_t(1) << 16;

        /* Adds k << shift to an address (k small enough not to overflow 64 bits after <8 bit shift). */
        SIpAddress addShifted(const SIpAddress& base, uint64_t k, uint32_t shift) noexcept {
            SIpAddress out = base;
            size_t len = out.length();
            size_t byteShift = shift / 8;
            uint64_t carry = k << (shift % 8);

            for (size_t i = len - (byteShift < len ? byteShift : len); i > 0 && carry != 0; --i) {
                uint64_t sum = uint64_t(out.bytes[i - 1]) + (carry & 0xff);
                out.bytes[i - 1] = uint8_t(sum & 0xff);
                carry = (carry >> 8) + (sum >> 8);
            }

            return out;
        }

        /* Parses an address member; unset when missing or invalid. */
        SIpAddress addressOf(const CJson& json, std::string_view key) {
            SIpAddress a;
            const CJson& v = json.get(key);
            if (v.isString()) {
                SIpAddress::parse(v.asString(), a);
            }

            return a;
        }

        /* Formats an address for JSON (null when unset). */
        CJson addressJson(const SIpAddress& a) {
            return a.isValid() ? CJson(a.toString()) : CJson();
        }

        /* Returns true when `a` may never be handed out by allocation. */
        bool isExcluded(const SIpamPool& pool, const SIpAddress& a) {
            SIpPrefix net = pool.subnet.network();
            if (a == net.address && pool.subnet.length < pool.subnet.address.bits() - 1) {
                // --> Network address (IPv4) or subnet-router anycast (IPv6).
                return true;
            }

            if (a.isV4() && pool.subnet.length < 31 && a == pool.subnet.last()) {
                return true;
            }

            if (pool.gateway.isValid() && a == pool.gateway) {
                return true;
            }

            for (const SIpAddress& r : pool.reserved) {
                if (r == a) {
                    return true;
                }
            }

            return false;
        }

        /* Finds a pool by id. */
        SIpamPool* findPool(std::vector<SIpamPool>& pools, const std::string& id) {
            for (SIpamPool& p : pools) {
                if (p.id == id) {
                    return &p;
                }
            }

            return nullptr;
        }

    }

    /* Returns Docker's default pools. */
    std::vector<SAddressPool> DefaultAddressPools() {
        static const struct { const char* base; uint8_t size; } DEFAULTS[] = {
            { "172.17.0.0/16", 16 }, { "172.18.0.0/16", 16 }, { "172.19.0.0/16", 16 },
            { "172.20.0.0/14", 16 }, { "172.24.0.0/14", 16 }, { "172.28.0.0/14", 16 },
            { "192.168.0.0/16", 20 },
        };

        std::vector<SAddressPool> out;
        for (const auto& d : DEFAULTS) {
            SAddressPool p;
            SIpPrefix::parse(d.base, p.base);
            p.size = d.size;
            out.push_back(p);
        }

        return out;
    }

    /* Parses daemon.json default-address-pools. */
    int32_t ParseAddressPools(const CJson& json, std::vector<SAddressPool>& out) {
        if (!json.isArray()) {
            return -EINVAL;
        }

        std::vector<SAddressPool> pools;
        for (size_t i = 0; i < json.size(); ++i) {
            const CJson& item = json.at(i);
            SAddressPool p;
            if (SIpPrefix::parse(item.get("base").asString(), p.base) != SBOX_OK) {
                return -EINVAL;
            }

            int64_t size = item.get("size").asInt(-1);
            if (size < p.base.length || size > int64_t(p.base.address.bits())) {
                return -EINVAL;
            }

            p.base = p.base.network();
            p.size = uint8_t(size);
            pools.push_back(p);
        }

        out = std::move(pools);
        return SBOX_OK;
    }

    /* Serializes a pool. */
    CJson SIpamPool::toJson() const {
        CJson j = CJson::object();
        j.set("id", id);
        j.set("space", space);
        j.set("subnet", subnet.toString());
        j.set("rangeStart", addressJson(rangeStart));
        j.set("rangeEnd", addressJson(rangeEnd));
        j.set("gateway", addressJson(gateway));

        CJson res = CJson::array();
        for (const SIpAddress& a : reserved) {
            res.push(a.toString());
        }

        j.set("reserved", std::move(res));

        CJson alloc = CJson::object();
        for (const auto& [addr, owner] : allocated) {
            alloc.set(addr.toString(), owner);
        }

        j.set("allocated", std::move(alloc));
        j.set("last", addressJson(last));
        j.set("dynamic", dynamic);
        j.set("labels", labels.isObject() ? labels : CJson::object());
        return j;
    }

    /* Parses a pool. */
    int32_t SIpamPool::fromJson(const CJson& json, SIpamPool& out) {
        SIpamPool p;
        p.id = json.get("id").asString();
        p.space = json.get("space").asString();
        if (p.id.empty() || SIpPrefix::parse(json.get("subnet").asString(), p.subnet) != SBOX_OK) {
            return -EINVAL;
        }

        p.rangeStart = addressOf(json, "rangeStart");
        p.rangeEnd = addressOf(json, "rangeEnd");
        p.gateway = addressOf(json, "gateway");
        p.last = addressOf(json, "last");
        p.dynamic = json.get("dynamic").asBool();
        p.labels = json.get("labels");

        const CJson& res = json.get("reserved");
        for (size_t i = 0; i < res.size(); ++i) {
            SIpAddress a;
            if (SIpAddress::parse(res.at(i).asString(), a) == SBOX_OK) {
                p.reserved.push_back(a);
            }
        }

        const CJson& alloc = json.get("allocated");
        if (alloc.isObject()) {
            for (size_t i = 0; i < alloc.size(); ++i) {
                SIpAddress a;
                if (SIpAddress::parse(alloc.keyAt(i), a) == SBOX_OK) {
                    p.allocated[a] = alloc.at(i).asString();
                }
            }
        }

        if (!p.rangeStart.isValid()) {
            p.rangeStart = p.subnet.network().address;
        }

        if (!p.rangeEnd.isValid()) {
            p.rangeEnd = p.subnet.last();
        }

        out = std::move(p);
        return SBOX_OK;
    }

    /* Creates the manager. */
    CIpam::CIpam(std::string stateDir, std::vector<SAddressPool> pools) : _dir(std::move(stateDir)) {
        for (SAddressPool& p : pools) {
            if (p.base.address.isV4()) {
                _pools4.push_back(p);
            }
            else if (p.base.address.isV6()) {
                _pools6.push_back(p);
            }
        }
    }

    /* Loads the state file. */
    int32_t CIpam::load(std::vector<SIpamPool>& pools) const {
        pools.clear();
        std::string text;
        int32_t r = CFile::readAll(CFile::join(_dir, "ipam.json"), text);
        if (r == -ENOENT) {
            return SBOX_OK;
        }

        if (r != SBOX_OK) {
            return r;
        }

        CJson doc;
        if (CJson::parse(text, doc) != SBOX_OK) {
            return -EBADMSG;
        }

        const CJson& list = doc.get("pools");
        for (size_t i = 0; i < list.size(); ++i) {
            SIpamPool p;
            if (SIpamPool::fromJson(list.at(i), p) == SBOX_OK) {
                pools.push_back(std::move(p));
            }
        }

        return SBOX_OK;
    }

    /* Saves the state file. */
    int32_t CIpam::save(const std::vector<SIpamPool>& pools) const {
        CJson doc = CJson::object();
        doc.set("version", 1);
        CJson list = CJson::array();
        for (const SIpamPool& p : pools) {
            list.push(p.toJson());
        }

        doc.set("pools", std::move(list));
        return CFile::writeAtomic(CFile::join(_dir, "ipam.json"), doc.dump(true) + "\n", 0600);
    }

    /* Allocates a pool. */
    TTask<int32_t> CIpam::requestPool(SIpamRequest request, SIpamPool& out) {
        int32_t r = CFile::makeDirs(_dir, 0700);
        if (r != SBOX_OK) {
            co_return r;
        }

        CFileLock lock;
        r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SIpamPool> pools;
        r = load(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (request.space.empty()) {
            request.space = "local";
        }

        SIpamPool pool;
        pool.space = request.space;
        pool.labels = request.labels.isObject() ? request.labels : CJson::object();

        auto overlapsExisting = [&](const SIpPrefix& subnet) {
            for (const SIpamPool& p : pools) {
                if (p.space == request.space && p.subnet.overlaps(subnet)) {
                    return true;
                }
            }

            return false;
        };

        if (request.subnet.isValid()) {
            pool.subnet = request.subnet.network();
            if (overlapsExisting(pool.subnet)) {
                co_return -EADDRINUSE;
            }
        }
        else {
            const std::vector<SAddressPool>& defaults = request.family == 6 ? _pools6 : _pools4;
            bool found = false;

            for (const SAddressPool& d : defaults) {
                uint32_t bits = d.base.address.bits();
                uint32_t splitBits = d.size - d.base.length;
                uint64_t count = splitBits >= 16 ? MAX_POOL_SPLITS : (uint64_t(1) << splitBits);

                for (uint64_t k = 0; k < count && !found; ++k) {
                    SIpPrefix candidate(addShifted(d.base.network().address, k, bits - d.size), d.size);
                    if (overlapsExisting(candidate)) {
                        continue;
                    }

                    bool avoided = false;
                    for (const SIpPrefix& a : request.avoid) {
                        avoided = avoided || a.overlaps(candidate);
                    }

                    if (!avoided) {
                        pool.subnet = candidate;
                        pool.dynamic = true;
                        found = true;
                    }
                }

                if (found) {
                    break;
                }
            }

            if (!found) {
                co_return -ENOSPC;
            }
        }

        pool.id = request.id.empty() ? request.space + "/" + pool.subnet.toString() : request.id;
        if (findPool(pools, pool.id)) {
            co_return -EEXIST;
        }

        // --> Allocation range: explicit start/end, else the sub-prefix, else the whole subnet.
        if (request.range.isValid()) {
            if (!pool.subnet.contains(request.range.address) || request.range.length < pool.subnet.length) {
                co_return -EINVAL;
            }

            pool.rangeStart = request.range.network().address;
            pool.rangeEnd = request.range.last();
        }
        else {
            pool.rangeStart = pool.subnet.network().address;
            pool.rangeEnd = pool.subnet.last();
        }

        if (request.rangeStart.isValid()) {
            pool.rangeStart = request.rangeStart;
        }

        if (request.rangeEnd.isValid()) {
            pool.rangeEnd = request.rangeEnd;
        }

        if (!pool.subnet.contains(pool.rangeStart) || !pool.subnet.contains(pool.rangeEnd)
            || pool.rangeEnd < pool.rangeStart)
        {
            co_return -EINVAL;
        }

        if (request.gateway.isValid()) {
            if (!pool.subnet.contains(request.gateway)) {
                co_return -EINVAL;
            }

            pool.gateway = request.gateway;
        }
        else if (request.reserveGateway && pool.subnet.length + 1 < int32_t(pool.subnet.address.bits())) {
            pool.gateway = pool.subnet.at(1);
        }

        for (const SIpAddress& a : request.reserved) {
            if (!pool.subnet.contains(a)) {
                co_return -EINVAL;
            }

            pool.reserved.push_back(a);
        }

        pools.push_back(pool);
        r = save(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        out = std::move(pool);
        co_return SBOX_OK;
    }

    /* Releases a pool. */
    TTask<int32_t> CIpam::releasePool(std::string id) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r == -ENOENT ? -ENOENT : r;
        }

        std::vector<SIpamPool> pools;
        r = load(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        for (size_t i = 0; i < pools.size(); ++i) {
            if (pools[i].id == id) {
                pools.erase(pools.begin() + ptrdiff_t(i));
                co_return save(pools);
            }
        }

        co_return -ENOENT;
    }

    /* Reads a pool. */
    TTask<int32_t> CIpam::getPool(std::string id, SIpamPool& out) {
        std::vector<SIpamPool> pools;
        int32_t r = co_await listPools(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        if (SIpamPool* p = findPool(pools, id)) {
            out = std::move(*p);
            co_return SBOX_OK;
        }

        co_return -ENOENT;
    }

    /* Reads every pool. */
    TTask<int32_t> CIpam::listPools(std::vector<SIpamPool>& out) {
        if (!CFile::exists(_dir)) {
            out.clear();
            co_return SBOX_OK;
        }

        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        co_return load(out);
    }

    /* Allocates an address. */
    TTask<int32_t> CIpam::requestAddress(std::string poolId, SIpAddress preferred, std::string owner, SIpAddress& out) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SIpamPool> pools;
        r = load(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        SIpamPool* pool = findPool(pools, poolId);
        if (!pool) {
            co_return -ENOENT;
        }

        if (preferred.isValid()) {
            if (!pool->subnet.contains(preferred)) {
                co_return -EINVAL;
            }

            // --> Explicit requests may take reserved addresses (the gateway itself, aux
            // addresses), only allocations collide.
            if (pool->allocated.count(preferred)) {
                co_return -EADDRINUSE;
            }

            pool->allocated[preferred] = owner;
            r = save(pools);
            if (r == SBOX_OK) {
                out = preferred;
            }

            co_return r;
        }

        uint64_t span = pool->rangeEnd.distanceFrom(pool->rangeStart);
        uint64_t size = span == UINT64_MAX ? UINT64_MAX : span + 1;
        uint64_t scan = size < MAX_SCAN ? size : MAX_SCAN;

        uint64_t startOffset = 0;
        if (pool->last.isValid()) {
            uint64_t d = pool->last.distanceFrom(pool->rangeStart);
            if (d != UINT64_MAX && d < size) {
                startOffset = d + 1 == size ? 0 : d + 1;
            }
        }

        for (uint64_t i = 0; i < scan; ++i) {
            uint64_t offset = startOffset + i;
            if (size != UINT64_MAX && offset >= size) {
                offset -= size;
            }

            SIpAddress candidate = pool->rangeStart.add(offset);
            if (isExcluded(*pool, candidate) || pool->allocated.count(candidate)) {
                continue;
            }

            pool->allocated[candidate] = owner;
            pool->last = candidate;
            r = save(pools);
            if (r == SBOX_OK) {
                out = candidate;
            }

            co_return r;
        }

        co_return -ENOSPC;
    }

    /* Releases an address. */
    TTask<int32_t> CIpam::releaseAddress(std::string poolId, SIpAddress address) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SIpamPool> pools;
        r = load(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        SIpamPool* pool = findPool(pools, poolId);
        if (!pool) {
            co_return -ENOENT;
        }

        if (pool->allocated.erase(address) == 0) {
            co_return SBOX_OK;
        }

        co_return save(pools);
    }

    /* Releases every address of an owner. */
    TTask<int32_t> CIpam::releaseOwner(std::string poolId, std::string owner) {
        CFileLock lock;
        int32_t r = co_await lock.lock(CFile::join(_dir, "ipam.lock"));
        if (r != SBOX_OK) {
            co_return r;
        }

        std::vector<SIpamPool> pools;
        r = load(pools);
        if (r != SBOX_OK) {
            co_return r;
        }

        SIpamPool* pool = findPool(pools, poolId);
        if (!pool) {
            co_return -ENOENT;
        }

        int32_t freed = 0;
        for (auto it = pool->allocated.begin(); it != pool->allocated.end();) {
            if (it->second == owner) {
                it = pool->allocated.erase(it);
                ++freed;
            }
            else {
                ++it;
            }
        }

        if (freed == 0) {
            co_return 0;
        }

        r = save(pools);
        co_return r == SBOX_OK ? freed : r;
    }

    /* Returns the addresses of an owner. */
    TTask<int32_t> CIpam::findOwner(std::string poolId, std::string owner, std::vector<SIpAddress>& out) {
        SIpamPool pool;
        int32_t r = co_await getPool(std::move(poolId), pool);
        if (r != SBOX_OK) {
            co_return r;
        }

        out.clear();
        for (const auto& [addr, who] : pool.allocated) {
            if (who == owner) {
                out.push_back(addr);
            }
        }

        co_return SBOX_OK;
    }

}
}
