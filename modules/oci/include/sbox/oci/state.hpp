#ifndef __INCLUDE_SBOX_OCI_STATE_HPP__
#define __INCLUDE_SBOX_OCI_STATE_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/oci/spec.hpp>

namespace sbox {
namespace oci {

    /**
     * Lifecycle status of a container (OCI runtime-spec "status", plus runc's "paused").
     */
    enum EContainerStatus : uint32_t {
        ECST_INVALID = 0,
        ECST_CREATING,          // --> `create` is still setting the container up.
        ECST_CREATED,           // --> The init waits at the start gate (exec.fifo exists).
        ECST_RUNNING,           // --> The user program runs.
        ECST_PAUSED,            // --> The cgroup is frozen.
        ECST_STOPPED,           // --> The init has exited (or the pid now names another process).
    };

    /**
     * Returns the OCI name of a status ("created", "running", ...).
     */
    SBOX_API const char* StatusName(EContainerStatus status) noexcept;

    /**
     * Parses a status name; ECST_INVALID when unknown.
     */
    SBOX_API EContainerStatus StatusFromName(std::string_view name) noexcept;

    /**
     * The OCI state of a container, as `state` prints it.
     */
    struct SState {
        std::string ociVersion = OCI_VERSION;
        std::string id;
        pid_t pid = 0;                          // --> 0 once stopped.
        EContainerStatus status = ECST_INVALID;
        std::string bundle;
        std::string rootfs;
        std::string created;                    // --> RFC 3339 with nanoseconds, UTC.
        std::string owner;
        std::vector<std::pair<std::string, std::string>> annotations;

        /**
         * Serializes in runc's member order (annotations omitted when empty).
         */
        CJson toJson() const;

        /**
         * Parses a state document (as written by toJson).
         */
        static int32_t fromJson(const CJson& doc, SState& out);
    };

    /**
     * What the runtime keeps in <root>/<id>/state.json between invocations.
     */
    struct SContainerRecord {
        std::string id;
        std::string bundle;                     // --> Absolute.
        std::string rootfs;                     // --> Absolute.
        std::string created;
        uint32_t ownerUid = 0;
        pid_t initPid = 0;                      // --> 0 while creating.
        uint64_t initStartTime = 0;             // --> /proc/<pid>/stat field 22 (pid reuse guard).
        std::string cgroupPath;                 // --> Relative to the hierarchy roots; empty when none.
        bool rootless = false;
        EContainerStatus lastStatus = ECST_CREATING;   // --> Last status this runtime wrote (a hint).
        SSpec config;                           // --> The configuration the container was created from.

        /**
         * Serializes the record.
         */
        CJson toJson() const;

        /**
         * Parses a record.
         * @return SBOX_OK or -EINVAL (with `error`).
         */
        static int32_t fromJson(const CJson& doc, SContainerRecord& out, std::string& error);
    };

    /**
     * Fields of /proc/<pid>/stat used to tell a live process from a dead or reused pid.
     */
    struct SProcStat {
        char state = '?';                       // --> R, S, D, Z, X, T ...
        pid_t ppid = 0;
        uint64_t startTime = 0;                 // --> Clock ticks since boot.
    };

    /**
     * Reads /proc/<pid>/stat.
     * @return SBOX_OK, -ESRCH when there is no such process, or another negated errno.
     */
    SBOX_API int32_t ReadProcStat(pid_t pid, SProcStat& out) noexcept;

    /**
     * Returns true when `pid` names a live (not zombie) process started at `startTime`.
     */
    SBOX_API bool ProcessAlive(pid_t pid, uint64_t startTime) noexcept;

    /**
     * Returns the current time in RFC 3339 form with nanoseconds, as Go's RFC3339Nano writes it
     * ("2026-10-04T12:51:27.232160881Z", trailing zeros of the fraction dropped).
     */
    SBOX_API std::string NowRfc3339Nano();

    /**
     * Checks a container id: letters, digits, '_', '+', '-', '.', not "." or "..", at most 1024
     * characters (runc's rules).
     */
    SBOX_API bool ValidContainerId(std::string_view id) noexcept;

}
}

#endif
