#ifndef __INCLUDE_SBOX_OCI_SPEC_HPP__
#define __INCLUDE_SBOX_OCI_SPEC_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <optional>

namespace sbox {
namespace oci {

    /**
     * OCI runtime-spec version this runtime writes and reports (config.json, state, features).
     */
    constexpr const char* OCI_VERSION = "1.2.1";

    /**
     * Lowest OCI runtime-spec version accepted in config.json.
     */
    constexpr const char* OCI_VERSION_MIN = "1.0.0";

    /**
     * `process.user`: the identity of the container process.
     */
    struct SUser {
        uint32_t uid = 0;
        uint32_t gid = 0;
        std::optional<uint32_t> umask;
        std::vector<uint32_t> additionalGids;
        std::string username;                   // --> Windows only; ignored on Linux.
    };

    /**
     * `process.consoleSize`.
     */
    struct SConsoleSize {
        uint32_t height = 0;
        uint32_t width = 0;
    };

    /**
     * `process.rlimits[]`.
     */
    struct SRlimitSpec {
        std::string type;                       // --> "RLIMIT_NOFILE", ...
        uint64_t hard = 0;
        uint64_t soft = 0;
    };

    /**
     * `process.capabilities`: capability names per set ("CAP_KILL", ...).
     */
    struct SCapabilitySets {
        std::vector<std::string> bounding;
        std::vector<std::string> effective;
        std::vector<std::string> inheritable;
        std::vector<std::string> permitted;
        std::vector<std::string> ambient;
    };

    /**
     * `process`: the container process (also the document `exec --process` reads).
     */
    struct SProcessSpec {
        bool terminal = false;
        std::optional<SConsoleSize> consoleSize;
        SUser user;
        std::vector<std::string> args;
        std::string commandLine;                // --> Windows only; ignored.
        std::vector<std::string> env;
        std::string cwd;
        std::optional<SCapabilitySets> capabilities;
        std::vector<SRlimitSpec> rlimits;
        bool noNewPrivileges = false;
        std::string apparmorProfile;            // --> Accepted, not enforced (warning).
        std::optional<int32_t> oomScoreAdj;
        std::string selinuxLabel;               // --> Accepted, not enforced (warning).
        CJson scheduler;                        // --> Accepted, ignored (null when absent).
        CJson ioPriority;                       // --> Accepted, ignored (null when absent).
        CJson execCPUAffinity;                  // --> Accepted, ignored (null when absent).
    };

    /**
     * `root`.
     */
    struct SRootSpec {
        std::string path;
        bool readonly = false;
    };

    /**
     * One user namespace ID mapping (`linux.uidMappings[]`, `mounts[].uidMappings[]`).
     */
    struct SIdMapping {
        uint32_t containerID = 0;
        uint32_t hostID = 0;
        uint32_t size = 0;
    };

    /**
     * `mounts[]`.
     */
    struct SMountEntry {
        std::string destination;
        std::string type;
        std::string source;
        std::vector<std::string> options;
        std::vector<SIdMapping> uidMappings;    // --> Idmapped mounts: parsed, refused at create.
        std::vector<SIdMapping> gidMappings;
    };

    /**
     * One hook: a program run with the container state on its standard input.
     */
    struct SHook {
        std::string path;
        std::vector<std::string> args;
        std::vector<std::string> env;
        std::optional<int32_t> timeout;         // --> Seconds.
    };

    /**
     * `hooks`.
     */
    struct SHooks {
        std::vector<SHook> prestart;            // --> Deprecated; runs right before createRuntime.
        std::vector<SHook> createRuntime;
        std::vector<SHook> createContainer;
        std::vector<SHook> startContainer;
        std::vector<SHook> poststart;
        std::vector<SHook> poststop;
    };

    /**
     * `linux.namespaces[]`.
     */
    struct SNamespaceEntry {
        std::string type;                       // --> pid, network, mount, ipc, uts, user, cgroup, time.
        std::string path;                       // --> Join this namespace instead of creating one.
    };

    /**
     * `linux.devices[]`: a device node created in the container.
     */
    struct SDeviceEntry {
        std::string type;                       // --> "c", "b", "u" or "p".
        std::string path;
        int64_t major = 0;
        int64_t minor = 0;
        std::optional<uint32_t> fileMode;
        std::optional<uint32_t> uid;
        std::optional<uint32_t> gid;
    };

    /**
     * `linux.resources.devices[]`: a device cgroup rule.
     */
    struct SDeviceRuleSpec {
        bool allow = false;
        std::string type;                       // --> "a", "c", "b" or empty (all).
        std::optional<int64_t> major;
        std::optional<int64_t> minor;
        std::string access;                     // --> Subset of "rwm"; empty means all.
    };

    /**
     * `linux.resources.memory`.
     */
    struct SMemorySpec {
        std::optional<int64_t> limit;
        std::optional<int64_t> reservation;
        std::optional<int64_t> swap;
        std::optional<int64_t> kernel;          // --> Deprecated; ignored.
        std::optional<int64_t> kernelTCP;       // --> Ignored.
        std::optional<uint64_t> swappiness;     // --> Ignored.
        std::optional<bool> disableOOMKiller;   // --> Ignored.
        std::optional<bool> useHierarchy;       // --> Ignored.
        std::optional<bool> checkBeforeUpdate;  // --> Ignored.
    };

    /**
     * `linux.resources.cpu`.
     */
    struct SCpuSpec {
        std::optional<uint64_t> shares;
        std::optional<int64_t> quota;
        std::optional<uint64_t> burst;          // --> Ignored.
        std::optional<uint64_t> period;
        std::optional<int64_t> realtimeRuntime; // --> Ignored.
        std::optional<uint64_t> realtimePeriod; // --> Ignored.
        std::string cpus;
        std::string mems;
        std::optional<int64_t> idle;            // --> Ignored.
    };

    /**
     * `linux.resources.pids`.
     */
    struct SPidsSpec {
        std::optional<int64_t> limit;
    };

    /**
     * `linux.resources.blockIO.weightDevice[]`.
     */
    struct SWeightDeviceSpec {
        int64_t major = 0;
        int64_t minor = 0;
        std::optional<uint16_t> weight;
        std::optional<uint16_t> leafWeight;
    };

    /**
     * `linux.resources.blockIO.throttle*Device[]`.
     */
    struct SThrottleDeviceSpec {
        int64_t major = 0;
        int64_t minor = 0;
        uint64_t rate = 0;
    };

    /**
     * `linux.resources.blockIO`.
     */
    struct SBlockIoSpec {
        std::optional<uint16_t> weight;
        std::optional<uint16_t> leafWeight;     // --> Ignored.
        std::vector<SWeightDeviceSpec> weightDevice;    // --> Ignored.
        std::vector<SThrottleDeviceSpec> throttleReadBpsDevice;
        std::vector<SThrottleDeviceSpec> throttleWriteBpsDevice;
        std::vector<SThrottleDeviceSpec> throttleReadIOPSDevice;
        std::vector<SThrottleDeviceSpec> throttleWriteIOPSDevice;
    };

    /**
     * `linux.resources.hugepageLimits[]` (ignored).
     */
    struct SHugepageLimitSpec {
        std::string pageSize;
        uint64_t limit = 0;
    };

    /**
     * `linux.resources` (also the document `update --resources` reads).
     */
    struct SResourcesSpec {
        std::vector<SDeviceRuleSpec> devices;
        std::optional<SMemorySpec> memory;
        std::optional<SCpuSpec> cpu;
        std::optional<SPidsSpec> pids;
        std::optional<SBlockIoSpec> blockIO;
        std::vector<SHugepageLimitSpec> hugepageLimits;
        CJson network;                          // --> Ignored (null when absent).
        CJson rdma;                             // --> Ignored (null when absent).
        std::vector<std::pair<std::string, std::string>> unified;
    };

    /**
     * `linux.seccomp.syscalls[].args[]`.
     */
    struct SSeccompArgSpec {
        uint32_t index = 0;
        uint64_t value = 0;
        uint64_t valueTwo = 0;
        std::string op;                         // --> "SCMP_CMP_EQ", ...
    };

    /**
     * `linux.seccomp.syscalls[]`.
     */
    struct SSyscallSpec {
        std::vector<std::string> names;
        std::string action;                     // --> "SCMP_ACT_ALLOW", ...
        std::optional<uint32_t> errnoRet;
        std::vector<SSeccompArgSpec> args;
    };

    /**
     * `linux.seccomp`.
     */
    struct SSeccompSpec {
        std::string defaultAction;
        std::optional<uint32_t> defaultErrnoRet;
        std::vector<std::string> architectures;
        std::vector<std::string> flags;
        std::string listenerPath;               // --> SCMP_ACT_NOTIFY is not supported.
        std::string listenerMetadata;
        std::vector<SSyscallSpec> syscalls;
    };

    /**
     * `linux`.
     */
    struct SLinuxSpec {
        std::vector<SIdMapping> uidMappings;
        std::vector<SIdMapping> gidMappings;
        std::vector<std::pair<std::string, std::string>> sysctl;
        std::optional<SResourcesSpec> resources;
        std::string cgroupsPath;
        std::vector<SNamespaceEntry> namespaces;
        std::vector<SDeviceEntry> devices;
        std::optional<SSeccompSpec> seccomp;
        std::string rootfsPropagation;
        std::vector<std::string> maskedPaths;
        std::vector<std::string> readonlyPaths;
        std::string mountLabel;                 // --> Ignored.
        CJson intelRdt;                         // --> Ignored (null when absent).
        CJson personality;                      // --> Ignored (null when absent).
        CJson timeOffsets;                      // --> Ignored (null when absent).
        CJson netDevices;                       // --> Refused at create when not empty.
        CJson memoryPolicy;                     // --> Ignored (null when absent).
    };

    /**
     * An OCI runtime configuration (config.json).
     *
     * Every field of the Linux part of runtime-spec 1.2 is represented, so a document round-trips
     * through ParseSpec/SpecToJson. Fields this runtime cannot enforce are still parsed (and
     * reported as warnings at create time) rather than rejected, as runc does for AppArmor or
     * SELinux on hosts without them.
     */
    struct SSpec {
        std::string ociVersion;
        std::optional<SProcessSpec> process;
        std::optional<SRootSpec> root;
        std::string hostname;
        std::string domainname;
        std::vector<SMountEntry> mounts;
        std::optional<SHooks> hooks;
        std::vector<std::pair<std::string, std::string>> annotations;
        std::optional<SLinuxSpec> linux_;       // --> "linux" is a predefined macro in GNU mode.
    };

    /**
     * Parses config.json.
     * @param doc The parsed document.
     * @param out Receives the configuration.
     * @param error Receives a message naming the offending field ("process.args: expected an
     *        array of strings") on failure.
     * @param warnings When not null, receives notes about unknown fields.
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseSpec(const CJson& doc, SSpec& out, std::string& error, std::vector<std::string>* warnings = nullptr);

    /**
     * Parses config.json text (see ParseSpec).
     */
    SBOX_API int32_t ParseSpecText(std::string_view text, SSpec& out, std::string& error, std::vector<std::string>* warnings = nullptr);

    /**
     * Reads and parses a config.json file (see ParseSpec).
     * @return SBOX_OK, -EINVAL, or the errno of reading the file.
     */
    SBOX_API int32_t LoadSpec(const std::string& path, SSpec& out, std::string& error, std::vector<std::string>* warnings = nullptr);

    /**
     * Serializes a configuration (fields that are not set are omitted, as runc does).
     */
    SBOX_API CJson SpecToJson(const SSpec& spec);

    /**
     * Parses a `process` object (also the `exec --process` document).
     * @param path Name used in error messages ("process").
     */
    SBOX_API int32_t ParseProcess(const CJson& doc, SProcessSpec& out, std::string& error, std::vector<std::string>* warnings = nullptr, std::string_view path = "process");

    /**
     * Serializes a `process` object.
     */
    SBOX_API CJson ProcessToJson(const SProcessSpec& process);

    /**
     * Parses a `linux.resources` object (also the `update --resources` document).
     */
    SBOX_API int32_t ParseResources(const CJson& doc, SResourcesSpec& out, std::string& error, std::vector<std::string>* warnings = nullptr, std::string_view path = "linux.resources");

    /**
     * Serializes a `linux.resources` object.
     */
    SBOX_API CJson ResourcesToJson(const SResourcesSpec& resources);

    /**
     * Options of ValidateSpec.
     */
    struct SValidateOptions {
        bool requireProcess = true;             // --> create/run need a process; a stored spec may not.
        bool rootless = false;                  // --> The runtime runs unprivileged.
    };

    /**
     * Checks a configuration for errors a runtime must refuse: missing root or process, relative
     * paths, unknown namespace types or duplicates, ID mappings without a user namespace, a
     * hostname without a private UTS namespace, invalid devices, rlimits and seccomp actions,
     * sysctls that are not namespaced, unknown propagation modes.
     * @param error Receives the first problem found.
     * @param warnings When not null, receives notes about fields that are accepted but not
     *        enforced (AppArmor, SELinux, personality, unknown capabilities ...).
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ValidateSpec(const SSpec& spec, std::string& error, std::vector<std::string>* warnings = nullptr, const SValidateOptions& options = SValidateOptions());

    /**
     * Returns runc's default configuration (`runc spec`), or its rootless variant (no network
     * namespace, a user namespace mapping `uid`/`gid` to root, /sys bound instead of mounted,
     * no device cgroup rules).
     * @param hostname The configured hostname ("sbox").
     */
    SBOX_API SSpec DefaultSpec(bool rootless = false, uint32_t uid = 0, uint32_t gid = 0, std::string_view hostname = "sbox");

    /**
     * Returns the RLIMIT_* number of an OCI rlimit name ("RLIMIT_NOFILE"), or -ENOENT.
     */
    SBOX_API int32_t RlimitFromName(std::string_view name) noexcept;

    /**
     * Returns the canonical name of a capability number ("CAP_KILL"), or an empty string.
     */
    SBOX_API std::string CapabilityName(int32_t cap);

    /**
     * Converts a namespace type name ("network") to the box namespace bit, or ENS_NONE.
     */
    SBOX_API uint32_t NamespaceFromName(std::string_view name) noexcept;

    /**
     * Returns the /proc/<pid>/ns/<file> name of a namespace type ("network" -> "net").
     */
    SBOX_API const char* NamespaceProcName(std::string_view type) noexcept;

}
}

#endif
