#include <sbox/oci/state.hpp>
#include <sbox/core/file.hpp>
#include "jsonread.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace sbox {
namespace oci {

    namespace {

        const char* const STATUS_NAMES[] = { "", "creating", "created", "running", "paused", "stopped" };

    }

    /* Returns the OCI name of a status. */
    const char* StatusName(EContainerStatus status) noexcept {
        return status <= ECST_STOPPED ? STATUS_NAMES[status] : "";
    }

    /* Parses a status name. */
    EContainerStatus StatusFromName(std::string_view name) noexcept {
        for (uint32_t i = ECST_CREATING; i <= ECST_STOPPED; ++i) {
            if (name == STATUS_NAMES[i]) {
                return EContainerStatus(i);
            }
        }

        return ECST_INVALID;
    }

    /* Serializes an OCI state. */
    CJson SState::toJson() const {
        CJson o = CJson::object();
        o.set("ociVersion", ociVersion);
        o.set("id", id);
        o.set("pid", int64_t(pid));
        o.set("status", StatusName(status));
        o.set("bundle", bundle);
        o.set("rootfs", rootfs);
        o.set("created", created);
        o.set("owner", owner);

        if (!annotations.empty()) {
            CJson a = CJson::object();
            for (const auto& [k, v] : annotations) {
                a.set(k, v);
            }

            o.set("annotations", std::move(a));
        }

        return o;
    }

    /* Parses an OCI state. */
    int32_t SState::fromJson(const CJson& doc, SState& out) {
        if (!doc.isObject()) {
            return -EINVAL;
        }

        out = SState();
        out.ociVersion = doc.get("ociVersion").asString();
        out.id = doc.get("id").asString();
        out.pid = pid_t(doc.get("pid").asInt());
        out.status = StatusFromName(doc.get("status").asString());
        out.bundle = doc.get("bundle").asString();
        out.rootfs = doc.get("rootfs").asString();
        out.created = doc.get("created").asString();
        out.owner = doc.get("owner").asString();

        const CJson& a = doc.get("annotations");
        for (size_t i = 0; a.isObject() && i < a.size(); ++i) {
            out.annotations.emplace_back(a.keyAt(i), a.at(i).asString());
        }

        return out.id.empty() ? -EINVAL : SBOX_OK;
    }

    /* Serializes a container record. */
    CJson SContainerRecord::toJson() const {
        CJson o = CJson::object();
        o.set("id", id);
        o.set("bundle", bundle);
        o.set("rootfs", rootfs);
        o.set("created", created);
        o.set("ownerUid", ownerUid);
        o.set("initProcessPid", int64_t(initPid));
        o.set("initProcessStartTime", initStartTime);
        o.set("cgroupPath", cgroupPath);
        o.set("rootless", rootless);
        o.set("status", StatusName(lastStatus));
        o.set("config", SpecToJson(config));
        return o;
    }

    /* Parses a container record. */
    int32_t SContainerRecord::fromJson(const CJson& doc, SContainerRecord& out, std::string& error) {
        out = SContainerRecord();
        error.clear();
        JsonReader r(error, nullptr);

        int64_t pid = 0;
        std::string status;
        if (!r.expectObject(doc, "state.json") || !r.str(doc, "id", out.id, "") || !r.str(doc, "bundle", out.bundle, "") ||
            !r.str(doc, "rootfs", out.rootfs, "") || !r.str(doc, "created", out.created, "") ||
            !r.u32(doc, "ownerUid", out.ownerUid, "") || !r.i64(doc, "initProcessPid", pid, "") ||
            !r.u64(doc, "initProcessStartTime", out.initStartTime, "") || !r.str(doc, "cgroupPath", out.cgroupPath, "") ||
            !r.boolean(doc, "rootless", out.rootless, "") || !r.str(doc, "status", status, "")) {
            return -EINVAL;
        }

        out.initPid = pid_t(pid);
        out.lastStatus = StatusFromName(status);

        if (const CJson* config = doc.find("config"); config && !config->isNull()) {
            std::string why;
            if (ParseSpec(*config, out.config, why) != SBOX_OK) {
                error = "state.json config: " + why;
                return -EINVAL;
            }
        }

        if (out.id.empty()) {
            error = "state.json: missing id";
            return -EINVAL;
        }

        return SBOX_OK;
    }

    /* Reads /proc/<pid>/stat. */
    int32_t ReadProcStat(pid_t pid, SProcStat& out) noexcept {
        if (pid <= 0) {
            return -ESRCH;
        }

        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%d/stat", int(pid));

        std::string text;
        int32_t rc = CFile::readAll(path, text, 64 * 1024);
        if (rc == -ENOENT) {
            return -ESRCH;
        }

        if (rc != SBOX_OK) {
            return rc;
        }

        // --> The command name (field 2) may contain spaces and parentheses: fields after it
        // start behind the last ')'.
        size_t close = text.rfind(')');
        if (close == std::string::npos || close + 2 >= text.size()) {
            return -EINVAL;
        }

        const char* p = text.c_str() + close + 2;
        out.state = *p;

        // --> Field 3 is the state; starttime is field 22, i.e. 19 fields further.
        int field = 3;
        while (*p && field < 22) {
            if (*p == ' ') {
                ++field;
                if (field == 4) {
                    out.ppid = pid_t(std::strtol(p + 1, nullptr, 10));
                } else if (field == 22) {
                    out.startTime = std::strtoull(p + 1, nullptr, 10);
                }
            }

            ++p;
        }

        return field == 22 ? SBOX_OK : -EINVAL;
    }

    /* Returns true when the pid names the live process started at startTime. */
    bool ProcessAlive(pid_t pid, uint64_t startTime) noexcept {
        SProcStat st;
        if (ReadProcStat(pid, st) != SBOX_OK) {
            return false;
        }

        return st.startTime == startTime && st.state != 'Z' && st.state != 'X' && st.state != 'x';
    }

    /* Returns the current time in RFC 3339 form with nanoseconds. */
    std::string NowRfc3339Nano() {
        struct timespec ts;
        ::clock_gettime(CLOCK_REALTIME, &ts);

        struct tm tm;
        ::gmtime_r(&ts.tv_sec, &tm);

        char base[32];
        std::strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);

        std::string out = base;
        if (ts.tv_nsec != 0) {
            char frac[16];
            std::snprintf(frac, sizeof(frac), "%09ld", long(ts.tv_nsec));
            std::string f = frac;
            while (!f.empty() && f.back() == '0') {
                f.pop_back();
            }

            out += "." + f;
        }

        out += "Z";
        return out;
    }

    /* Checks a container id. */
    bool ValidContainerId(std::string_view id) noexcept {
        if (id.empty() || id.size() > 1024 || id == "." || id == "..") {
            return false;
        }

        for (char c : id) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '+' ||
                      c == '-' || c == '.';
            if (!ok) {
                return false;
            }
        }

        return true;
    }

}
}
