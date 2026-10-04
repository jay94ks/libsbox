#ifndef __INCLUDE_SBOX_NET_CNI_HPP__
#define __INCLUDE_SBOX_NET_CNI_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>

namespace sbox {
namespace net {

    /**
     * One CNI plugin invocation: the CNI_* environment and the network configuration on stdin.
     */
    struct SCniRequest {
        std::string command;        // --> CNI_COMMAND: ADD, DEL, CHECK, VERSION.
        std::string containerId;    // --> CNI_CONTAINERID.
        std::string netns;          // --> CNI_NETNS.
        std::string ifName;         // --> CNI_IFNAME.
        std::string args;           // --> CNI_ARGS ("K=V;K=V").
        std::string path;           // --> CNI_PATH.
        std::string config;         // --> Network configuration JSON (stdin).
        std::string hostNetns;      // --> Embedding/testing aid: namespace treated as the host.
    };

    /**
     * Reads a request from the process environment (CNI_*), with `config` read by the caller.
     */
    SBOX_API SCniRequest CniRequestFromEnvironment();

    /**
     * CNI error codes of the specification (plugin-specific errors use 100 and up).
     */
    enum ECniError : int32_t {
        ECNI_INCOMPATIBLE_VERSION = 1,
        ECNI_UNSUPPORTED_FIELD    = 2,
        ECNI_UNKNOWN_CONTAINER    = 3,
        ECNI_INVALID_ENVIRONMENT  = 4,
        ECNI_IO_FAILURE           = 5,
        ECNI_DECODE_FAILURE       = 6,
        ECNI_INVALID_CONFIG       = 7,
        ECNI_TRY_AGAIN_LATER      = 11,
        ECNI_PLUGIN_FAILURE       = 100,   // --> sbox: an operation failed (details carry errno text).
        ECNI_CHECK_FAILED         = 101,   // --> sbox: CHECK found the container's network broken.
    };

    /**
     * Runs a CNI command (spec 1.0.0; results also rendered for 0.3.x/0.4.0 configurations).
     *
     * Supported configuration ("type" is the binary name, sbox-cni):
     *   {"cniVersion":"1.0.0","name":"net","type":"sbox-cni","driver":"bridge|macvlan|ipvlan",
     *    "bridge":"cni0","ipMasq":true,"mtu":1500,"master":"eth0","mode":"bridge",
     *    "stateDir":"/var/lib/sbox/net",
     *    "ipam":{"type":"sbox|host-local|dhcp","subnet":"10.1.0.0/24","rangeStart":...,"rangeEnd":...,
     *            "gateway":...,"ranges":[[{"subnet":...}]],"routes":[{"dst":"0.0.0.0/0"}]},
     *    "capabilities":{"portMappings":true},"runtimeConfig":{"portMappings":[...]}}
     * The network is created on first ADD (bridge, gateway, NAT) and kept afterwards; endpoints
     * are found again by (CNI_CONTAINERID, CNI_IFNAME) for DEL and CHECK.
     *
     * @param output Receives the JSON to print on stdout (result or error object).
     * @return The process exit code: 0 on success, 1 on error.
     */
    SBOX_API TTask<int32_t> RunCni(SCniRequest request, std::string& output);

}
}

#endif
